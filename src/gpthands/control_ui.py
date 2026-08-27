from __future__ import annotations

import html
import json
import secrets
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .approval import ApprovalManager
from .diagnostics import diagnostic_report
from .pending_approvals import PendingApprovalStore
from .risk import RiskLevel
from .state import state_root
from .trust import WorkspaceTrustStore


class ControlUIError(RuntimeError):
    pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, *, workspace: Path) -> None:
        super().__init__(address, handler)
        self.workspace = workspace.resolve(strict=True)
        self.csrf_token = secrets.token_urlsafe(32)
        self.trust_store = WorkspaceTrustStore()
        self.pending_store = PendingApprovalStore()
        self.approvals = ApprovalManager(state_root() / "approval.key")

    def switch_workspace(self, candidate: str) -> None:
        path = Path(candidate).expanduser().resolve(strict=True)
        if not path.is_dir():
            raise ControlUIError("workspace switch target must be a directory")
        if not self.trust_store.is_trusted(path):
            raise ControlUIError("workspace switch target is not explicitly trusted")
        self.workspace = path

    def server_close(self) -> None:
        try:
            self.approvals.close()
            self.pending_store.close()
        finally:
            super().server_close()


class ControlHandler(BaseHTTPRequestHandler):
    server_version = "GPTHandsControl/1.0"

    def log_message(self, format: str, *args) -> None:
        return

    def _headers(self, status=HTTPStatus.OK, content_type="text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        self.end_headers()

    def _html(self, body: str, *, status=HTTPStatus.OK) -> None:
        self._headers(status)
        self.wfile.write(("<!doctype html><meta charset=utf-8><title>GPTHands</title>" + body).encode("utf-8"))

    def _require_loopback_host(self) -> None:
        value = self.headers.get("Host", "").strip()
        if not value or "@" in value or any(ch in value for ch in "\r\n"):
            raise ControlUIError("invalid local UI Host header")
        try:
            parsed = urllib.parse.urlsplit("//" + value)
            hostname = (parsed.hostname or "").lower()
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("userinfo is not allowed")
            if parsed.port is not None and not 0 <= parsed.port <= 65535:
                raise ValueError("invalid port")
        except ValueError as exc:
            raise ControlUIError("invalid local UI Host header") from exc
        if hostname not in {"127.0.0.1", "localhost"}:
            raise ControlUIError("local UI rejected non-loopback Host header")

    def _form(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ControlUIError("invalid content length") from exc
        if not 0 <= length <= 8192:
            raise ControlUIError("request body too large")
        raw = self.rfile.read(length).decode("utf-8")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True, max_num_fields=20)
        return {key: values[-1] for key, values in parsed.items() if values}

    def _require_csrf(self, form: dict[str, str]) -> None:
        supplied = form.get("csrf", "")
        if not secrets.compare_digest(supplied, self.server.csrf_token):
            raise ControlUIError("invalid local UI authorization token")

    @staticmethod
    def _valid_action_hash(action_hash: str) -> bool:
        return len(action_hash) == 64 and all(ch in "0123456789abcdef" for ch in action_hash)

    def _issue_token(self, *, risk: RiskLevel, action_hash: str, seconds: int) -> str:
        if not self._valid_action_hash(action_hash):
            raise ControlUIError("action hash must be 64 lowercase hexadecimal characters")
        return self.server.approvals.issue(
            workspace=self.server.workspace,
            risk=risk,
            ttl_seconds=seconds,
            action_hash=action_hash,
        )

    def _token_page(self, token: str, *, action_hash: str) -> None:
        self._html(
            "<h1>Approval issued</h1><p>This token is one-time, short-lived, and bound to the exact action.</p>"
            f"<p><code>{html.escape(action_hash)}</code></p>"
            f"<textarea cols=100 rows=6 readonly>{html.escape(token)}</textarea><p><a href='/'>Back</a></p>"
        )

    def do_GET(self) -> None:
        try:
            self._require_loopback_host()
        except ControlUIError as exc:
            self._html(f"<h1>Request refused</h1><pre>{html.escape(str(exc))}</pre>", status=HTTPStatus.BAD_REQUEST)
            return

        if self.path == "/api/status":
            report = diagnostic_report(self.server.workspace)
            report["trusted"] = self.server.trust_store.is_trusted(self.server.workspace)
            report["trusted_workspaces"] = self.server.trust_store.list()
            report["pending_approvals"] = self.server.pending_store.list_for_workspace(self.server.workspace)
            self._headers(content_type="application/json; charset=utf-8")
            self.wfile.write(json.dumps(report, ensure_ascii=False).encode("utf-8"))
            return
        if self.path not in {"/", "/index.html"}:
            self._html("<h1>Not found</h1>", status=HTTPStatus.NOT_FOUND)
            return

        trusted = self.server.trust_store.is_trusted(self.server.workspace)
        trusted_rows = self.server.trust_store.list()
        pending = self.server.pending_store.list_for_workspace(self.server.workspace)
        report = diagnostic_report(self.server.workspace)
        rows = "".join(
            f"<tr><td>{html.escape(c['name'])}</td><td>{html.escape(c['status'])}</td><td>{html.escape(c['detail'])}</td></tr>"
            for c in report["checks"]
        )
        token = html.escape(self.server.csrf_token)
        workspace = html.escape(str(self.server.workspace))
        trust_action = "untrust" if trusted else "trust"
        trust_label = "Remove trust" if trusted else "Trust this workspace"
        switch_options = "".join(
            f'<option value="{html.escape(str(row.get("path", "")))}"'
            f'{" selected" if str(row.get("path", "")) == str(self.server.workspace) else ""}>'
            f'{html.escape(str(row.get("label") or row.get("path") or "workspace"))}</option>'
            for row in trusted_rows
            if row.get("path")
        )
        switch_form = (
            f'<form method=post action=/switch><input type=hidden name=csrf value="{token}">'
            f'<select name=workspace>{switch_options}</select><button>Switch workspace</button></form>'
            if switch_options else "<p class=muted>No trusted workspace saved yet.</p>"
        )
        pending_rows = "".join(
            "<tr>"
            f"<td>{html.escape(str(row.get('risk', '')))}</td>"
            f"<td><code>{html.escape(str(row.get('action_hash', '')))}</code></td>"
            f"<td>{html.escape(str(row.get('last_seen_at', '')))}</td>"
            "<td><form method=post action=/approve-pending>"
            f'<input type=hidden name=csrf value="{token}">'
            f'<input type=hidden name=action_hash value="{html.escape(str(row.get("action_hash", "")))}">'
            "<input type=hidden name=seconds value=300>"
            "<button>Approve 5 min</button></form></td></tr>"
            for row in pending
        ) or "<tr><td colspan=4 class=muted>No action is waiting for approval.</td></tr>"

        body = f"""
<style>
body{{font:14px system-ui;max-width:1040px;margin:36px auto;padding:0 18px;color:#1f2328}}h1{{margin-bottom:4px}}.muted{{color:#667085}}.ok{{color:#067647}}.warn{{color:#b54708}}table{{border-collapse:collapse;width:100%;margin:18px 0}}td,th{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}}fieldset{{margin:18px 0;padding:14px}}input,select,button{{padding:8px;margin:4px}}code{{word-break:break-all}}
</style>
<h1>GPTHands v1 Control</h1>
<p class=muted>Loopback-only local control surface. No credentials or command contents are rendered here.</p>
<p><strong>Workspace:</strong> <code>{workspace}</code></p>
<p><strong>Trust:</strong> {'<span class=ok>trusted</span>' if trusted else '<span class=warn>not trusted</span>'}</p>
<form method=post action=/{trust_action}><input type=hidden name=csrf value="{token}"><button>{trust_label}</button></form>
<fieldset><legend>Trusted workspace switcher</legend>{switch_form}</fieldset>
<h2>Pending approvals</h2>
<table><tr><th>Risk</th><th>Exact action hash</th><th>Last seen</th><th>Action</th></tr>{pending_rows}</table>
<h2>Diagnostics</h2><table><tr><th>Check</th><th>Status</th><th>Detail</th></tr>{rows}</table>
<fieldset><legend>Manual action-bound approval</legend>
<form method=post action=/approve>
<input type=hidden name=csrf value="{token}">
<label>Risk <select name=risk>{''.join(f'<option>{r.name}</option>' for r in RiskLevel)}</select></label>
<label>TTL seconds <input name=seconds value=300 inputmode=numeric></label><br>
<label>Action hash <input name=action_hash size=70 required></label><br>
<button>Issue one-time approval</button>
</form></fieldset>
"""
        self._html(body)

    def do_POST(self) -> None:
        try:
            self._require_loopback_host()
            form = self._form()
            self._require_csrf(form)
            if self.path == "/trust":
                self.server.trust_store.trust(self.server.workspace)
                return self._redirect()
            if self.path == "/untrust":
                self.server.trust_store.untrust(self.server.workspace)
                return self._redirect()
            if self.path == "/switch":
                self.server.switch_workspace(form.get("workspace", ""))
                return self._redirect()
            if self.path == "/approve-pending":
                action_hash = form.get("action_hash", "").strip()
                matches = [
                    row for row in self.server.pending_store.list_for_workspace(self.server.workspace)
                    if row.get("action_hash") == action_hash
                ]
                if len(matches) != 1:
                    raise ControlUIError("pending action no longer exists for this workspace")
                risk = RiskLevel.parse(str(matches[0].get("risk", "")))
                seconds = int(form.get("seconds", "300"))
                token = self._issue_token(risk=risk, action_hash=action_hash, seconds=seconds)
                self.server.pending_store.remove(workspace=self.server.workspace, action_hash=action_hash)
                return self._token_page(token, action_hash=action_hash)
            if self.path == "/approve":
                risk = RiskLevel.parse(form.get("risk", ""))
                action_hash = form.get("action_hash", "").strip()
                seconds = int(form.get("seconds", "300"))
                token = self._issue_token(risk=risk, action_hash=action_hash, seconds=seconds)
                self.server.pending_store.remove(workspace=self.server.workspace, action_hash=action_hash)
                return self._token_page(token, action_hash=action_hash)
            self._html("<h1>Not found</h1>", status=HTTPStatus.NOT_FOUND)
        except (ValueError, ControlUIError) as exc:
            self._html(f"<h1>Request refused</h1><pre>{html.escape(str(exc))}</pre>", status=HTTPStatus.BAD_REQUEST)

    def _redirect(self) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


def create_control_server(workspace: Path, *, port: int = 0) -> _Server:
    if not 0 <= port <= 65535:
        raise ControlUIError("port is invalid")
    return _Server(("127.0.0.1", port), ControlHandler, workspace=workspace)


def serve_control_ui(workspace: Path, *, port: int = 0, open_browser: bool = True) -> int:
    server = create_control_server(workspace, port=port)
    host, actual_port = server.server_address[:2]
    url = f"http://{host}:{actual_port}/"
    print(url, flush=True)
    if open_browser:
        webbrowser.open(url, new=1, autoraise=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
