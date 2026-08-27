from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .approval import ApprovalError, ApprovalManager
from .audit import AuditLogger, content_fingerprint, redact_text
from .policy import Policy, PolicyError, default_policy_path
from .risk import RiskLevel
from .sandbox import SandboxError, SandboxRunner

SERVER_NAME = "GPTHands"
SERVER_VERSION = "0.2.0"
PROTOCOL_VERSION = "2025-06-18"


def _tool(name: str, description: str, properties: dict[str, Any], required: list[str], *, read_only: bool) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": not read_only,
            "openWorldHint": False,
        },
    }


TOOLS = [
    _tool("workspace_info", "Return workspace, policy authority path, active leases, and sandbox settings.", {}, [], read_only=True),
    _tool("read_file", "Read a UTF-8 text file inside the workspace with secret redaction.", {"target": {"type": "string"}}, ["target"], read_only=True),
    _tool("list_dir", "List one directory inside the workspace.", {"target": {"type": "string", "default": "."}}, [], read_only=True),
    _tool(
        "grep",
        "Search bounded UTF-8 text below a workspace path.",
        {"pattern": {"type": "string"}, "target": {"type": "string", "default": "."}, "regex": {"type": "boolean", "default": False}},
        ["pattern"],
        read_only=True,
    ),
    _tool(
        "write_file",
        "Create or replace one UTF-8 file. Write lease required; overwrite may require human approval.",
        {
            "target": {"type": "string"},
            "content": {"type": "string"},
            "overwrite": {"type": "boolean", "default": False},
            "approval_token": {"type": "string"},
        },
        ["target", "content"],
        read_only=False,
    ),
    _tool(
        "preview_edit",
        "Preview a full-file edit and receive a one-time preview_id plus base SHA-256.",
        {"target": {"type": "string"}, "new_content": {"type": "string"}},
        ["target", "new_content"],
        read_only=True,
    ),
    _tool(
        "apply_edit",
        "Apply a previously previewed edit atomically. Write lease and matching preview_id are required.",
        {
            "target": {"type": "string"},
            "new_content": {"type": "string"},
            "base_sha256": {"type": "string"},
            "preview_id": {"type": "string"},
            "approval_token": {"type": "string"},
        },
        ["target", "new_content", "base_sha256", "preview_id"],
        read_only=False,
    ),
    _tool(
        "run_command",
        "Run an allowlisted argv command inside the OS sandbox. Process/network leases and approvals are enforced.",
        {
            "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "cwd": {"type": "string", "default": "."},
            "approval_token": {"type": "string"},
        },
        ["argv"],
        read_only=False,
    ),
    _tool("git_status", "Run curated read-only git status inside the OS sandbox.", {}, [], read_only=True),
    _tool(
        "git_diff",
        "Run curated read-only git diff inside the OS sandbox.",
        {"staged": {"type": "boolean", "default": False}, "path": {"type": "string"}},
        [],
        read_only=True,
    ),
]


class GPTHandsServer:
    def __init__(
        self,
        policy: Policy,
        audit: AuditLogger,
        *,
        approvals: ApprovalManager | None = None,
        sandbox: SandboxRunner | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.approvals = approvals or ApprovalManager(_default_approval_key_path())
        self.sandbox = sandbox or SandboxRunner(require_os_sandbox=policy.require_os_sandbox)
        self._previews: set[str] = set()

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        request_id = message.get("id")
        if request_id is None:
            return None
        method = message.get("method", "")
        params = message.get("params") or {}

        try:
            if method == "initialize":
                client_version = params.get("protocolVersion", PROTOCOL_VERSION) if isinstance(params, dict) else PROTOCOL_VERSION
                result = {
                    "protocolVersion": client_version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "instructions": (
                        "GPTHands v0.2 keeps authority outside repository content. Mutable capabilities are lease-bound, "
                        "high-risk actions require signed human approval, and commands run in an OS sandbox when required."
                    ),
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                if not isinstance(params, dict):
                    raise ValueError("tools/call params must be an object")
                name = params.get("name")
                arguments = params.get("arguments") or {}
                if not isinstance(name, str) or not isinstance(arguments, dict):
                    raise ValueError("tools/call requires string name and object arguments")
                result = self._call_tool(request_id, name, arguments)
            else:
                return _rpc_error(request_id, -32601, f"method not found: {method}")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except (PolicyError, ApprovalError, SandboxError, ValueError, OSError) as exc:
            return _rpc_error(request_id, -32000, redact_text(str(exc)))
        except Exception as exc:
            return _rpc_error(request_id, -32603, f"internal error: {type(exc).__name__}")

    def _call_tool(self, request_id: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            if name == "workspace_info":
                text, detail = self._workspace_info()
            elif name == "read_file":
                text, detail = self._read_file(args)
            elif name == "list_dir":
                text, detail = self._list_dir(args)
            elif name == "grep":
                text, detail = self._grep(args)
            elif name == "write_file":
                text, detail = self._write_file(args)
            elif name == "preview_edit":
                text, detail = self._preview_edit(args)
            elif name == "apply_edit":
                text, detail = self._apply_edit(args)
            elif name == "run_command":
                text, detail = self._run_command(args)
            elif name == "git_status":
                text, detail = self._git_status()
            elif name == "git_diff":
                text, detail = self._git_diff(args)
            else:
                raise ValueError(f"unknown tool: {name}")

            self.audit.record(request_id=request_id, tool=name, outcome="allowed", detail=detail)
            return {"content": [{"type": "text", "text": redact_text(text)}], "isError": False}
        except Exception as exc:
            self.audit.record(
                request_id=request_id,
                tool=name,
                outcome="denied_or_failed",
                detail={"error": redact_text(str(exc))[:500]},
            )
            return {"content": [{"type": "text", "text": redact_text(str(exc))}], "isError": True}

    def _workspace_info(self) -> tuple[str, dict[str, Any]]:
        payload = {
            "workspace": str(self.policy.workspace),
            "policy_path": str(self.policy.policy_path),
            "allow_write": self.policy.allow_write,
            "allow_process": self.policy.allow_process,
            "allow_network_commands": self.policy.allow_network_commands,
            "require_os_sandbox": self.policy.require_os_sandbox,
            "approval_required_from": self.policy.approval_required_from.name,
            "allowed_commands": list(self.policy.allowed_commands),
            "leases": {
                "write_until": self.policy.write_lease_until,
                "process_until": self.policy.process_lease_until,
                "network_until": self.policy.network_lease_until,
            },
        }
        return json.dumps(payload, indent=2), {"capabilities_only": True}

    def _read_file(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        target = _require_str(args, "target")
        path = self.policy.resolve_path(target, must_exist=True)
        if not path.is_file():
            raise PolicyError("target is not a file")
        data = path.read_bytes()
        if len(data) > self.policy.max_read_bytes:
            raise PolicyError("file exceeds max_read_bytes")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError("binary/non-UTF-8 files are not readable") from exc
        return text, {"target": _relative(self.policy.workspace, path), "bytes": len(data), "risk": "READ"}

    def _list_dir(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        target = args.get("target", ".")
        if not isinstance(target, str):
            raise ValueError("target must be a string")
        path = self.policy.resolve_path(target, must_exist=True)
        if not path.is_dir():
            raise PolicyError("target is not a directory")
        rows: list[str] = []
        for child in sorted(path.iterdir(), key=lambda p: p.name.lower()):
            try:
                self.policy.resolve_path(_relative(self.policy.workspace, child), must_exist=True)
            except PolicyError:
                rows.append(f"[blocked]\t{child.name}")
                continue
            rows.append(f"{'dir' if child.is_dir() else 'file'}\t{child.name}")
        return "\n".join(rows), {"target": _relative(self.policy.workspace, path), "entries": len(rows), "risk": "READ"}

    def _grep(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        pattern = _require_str(args, "pattern")
        target = args.get("target", ".")
        use_regex = args.get("regex", False)
        if not isinstance(target, str) or not isinstance(use_regex, bool):
            raise ValueError("target must be string and regex must be boolean")
        root = self.policy.resolve_path(target, must_exist=True)
        matcher = re.compile(pattern) if use_regex else None
        results: list[str] = []
        scanned = 0
        candidates = [root] if root.is_file() else root.rglob("*")
        for path in candidates:
            if len(results) >= 200 or scanned >= 5000 or not path.is_file():
                if len(results) >= 200 or scanned >= 5000:
                    break
                continue
            try:
                rel = _relative(self.policy.workspace, path)
                safe = self.policy.resolve_path(rel, must_exist=True)
                if safe.stat().st_size > min(self.policy.max_read_bytes, 2_000_000):
                    continue
                text = safe.read_text(encoding="utf-8")
            except (PolicyError, OSError, UnicodeDecodeError):
                continue
            scanned += 1
            for line_no, line in enumerate(text.splitlines(), 1):
                if bool(matcher.search(line)) if matcher else pattern in line:
                    results.append(f"{rel}:{line_no}:{redact_text(line)}")
                    if len(results) >= 200:
                        break
        return "\n".join(results), {"target": target, "files_scanned": scanned, "matches": len(results), "risk": "READ"}

    def _write_file(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        self.policy.require_write()
        target = _require_str(args, "target")
        content = _require_str(args, "content", allow_empty=True)
        overwrite = args.get("overwrite", False)
        if not isinstance(overwrite, bool):
            raise ValueError("overwrite must be boolean")
        path = self.policy.resolve_path(target, must_exist=False)
        risk = RiskLevel.DESTRUCTIVE if path.exists() and overwrite else RiskLevel.WRITE
        action_hash = _action_hash("write_file", {"target": target, "overwrite": overwrite, "content": content_fingerprint(content)})
        self._require_approval(args.get("approval_token"), risk=risk, action_hash=action_hash)
        self._atomic_write(path, content, overwrite=overwrite)
        return "written", {"target": target, "overwrite": overwrite, "content": content_fingerprint(content), "risk": risk.name}

    def _preview_edit(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        target = _require_str(args, "target")
        new_content = _require_str(args, "new_content", allow_empty=True)
        path = self.policy.resolve_path(target, must_exist=True)
        if not path.is_file():
            raise PolicyError("target is not a file")
        old = path.read_text(encoding="utf-8")
        if len(new_content.encode("utf-8")) > self.policy.max_write_bytes:
            raise PolicyError("new_content exceeds max_write_bytes")
        base_sha = hashlib.sha256(old.encode("utf-8")).hexdigest()
        preview_id = _action_hash("apply_edit", {"target": target, "base_sha256": base_sha, "new_sha256": hashlib.sha256(new_content.encode()).hexdigest()})
        self._previews.add(preview_id)
        diff = "".join(difflib.unified_diff(old.splitlines(True), new_content.splitlines(True), fromfile=f"a/{target}", tofile=f"b/{target}"))
        payload = {"preview_id": preview_id, "base_sha256": base_sha, "diff": diff or "[no changes]"}
        return json.dumps(payload, ensure_ascii=False, indent=2), {"target": target, "risk": "READ", "preview_id": preview_id}

    def _apply_edit(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        self.policy.require_write()
        target = _require_str(args, "target")
        new_content = _require_str(args, "new_content", allow_empty=True)
        base_sha = _require_str(args, "base_sha256")
        preview_id = _require_str(args, "preview_id")
        path = self.policy.resolve_path(target, must_exist=True)
        current = path.read_text(encoding="utf-8")
        current_sha = hashlib.sha256(current.encode("utf-8")).hexdigest()
        if current_sha != base_sha:
            raise PolicyError("file changed since preview; generate a new preview")
        expected_preview = _action_hash("apply_edit", {"target": target, "base_sha256": base_sha, "new_sha256": hashlib.sha256(new_content.encode()).hexdigest()})
        if preview_id != expected_preview or preview_id not in self._previews:
            raise PolicyError("valid one-time preview_id required before apply_edit")
        risk = RiskLevel.WRITE
        self._require_approval(args.get("approval_token"), risk=risk, action_hash=expected_preview)
        self._atomic_write(path, new_content, overwrite=True)
        self._previews.remove(preview_id)
        return "applied", {"target": target, "base_sha256": base_sha, "new_sha256": hashlib.sha256(new_content.encode()).hexdigest(), "risk": risk.name}

    def _run_command(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        argv = args.get("argv")
        if not isinstance(argv, list):
            raise ValueError("argv must be an array")
        checked, risk = self.policy.validate_command(argv)
        cwd_value = args.get("cwd", ".")
        if not isinstance(cwd_value, str):
            raise ValueError("cwd must be a string")
        cwd = self.policy.resolve_path(cwd_value, must_exist=True)
        if not cwd.is_dir():
            raise PolicyError("cwd is not a directory")
        action_hash = _action_hash("run_command", {"argv": checked, "cwd": _relative(self.policy.workspace, cwd)})
        self._require_approval(args.get("approval_token"), risk=risk, action_hash=action_hash)
        completed, backend = self.sandbox.run(
            command=checked,
            workspace=self.policy.workspace,
            cwd=cwd,
            allow_write=self.policy.allow_write,
            allow_network=self.policy.allow_network_commands and risk >= RiskLevel.NETWORK,
            env=_safe_env(),
            timeout=self.policy.max_command_seconds,
            max_output_bytes=self.policy.max_output_bytes,
        )
        output = completed.stdout.decode("utf-8", errors="replace")
        return f"exit_code={completed.returncode}\n{output}", {
            "program": Path(checked[0]).name,
            "argc": len(checked),
            "cwd": _relative(self.policy.workspace, cwd),
            "exit_code": completed.returncode,
            "output_bytes": len(completed.stdout),
            "risk": risk.name,
            "sandbox": backend,
        }

    def _git_status(self) -> tuple[str, dict[str, Any]]:
        completed, backend = self._run_curated_git(["git", "status", "--short", "--branch"])
        return completed.stdout.decode("utf-8", errors="replace"), {"risk": "READ", "sandbox": backend, "exit_code": completed.returncode}

    def _git_diff(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        staged = args.get("staged", False)
        path_value = args.get("path")
        if not isinstance(staged, bool) or (path_value is not None and not isinstance(path_value, str)):
            raise ValueError("staged must be boolean and path must be string")
        command = ["git", "diff", "--no-ext-diff"]
        if staged:
            command.append("--cached")
        if path_value:
            safe = self.policy.resolve_path(path_value, must_exist=False)
            command += ["--", _relative(self.policy.workspace, safe)]
        completed, backend = self._run_curated_git(command)
        return completed.stdout.decode("utf-8", errors="replace"), {"risk": "READ", "sandbox": backend, "exit_code": completed.returncode}

    def _run_curated_git(self, command: list[str]):
        return self.sandbox.run(
            command=command,
            workspace=self.policy.workspace,
            cwd=self.policy.workspace,
            allow_write=False,
            allow_network=False,
            env=_safe_env(),
            timeout=min(self.policy.max_command_seconds, 30),
            max_output_bytes=self.policy.max_output_bytes,
        )

    def _require_approval(self, token: object, *, risk: RiskLevel, action_hash: str) -> None:
        if not self.policy.approval_required(risk):
            return
        if token is not None and not isinstance(token, str):
            raise ValueError("approval_token must be a string")
        self.approvals.validate(token if isinstance(token, str) else None, workspace=self.policy.workspace, minimum_risk=risk, action_hash=action_hash)

    def _atomic_write(self, path: Path, content: str, *, overwrite: bool) -> None:
        data = content.encode("utf-8")
        if len(data) > self.policy.max_write_bytes:
            raise PolicyError("content exceeds max_write_bytes")
        parent = self.policy.resolve_path(_relative(self.policy.workspace, path.parent), must_exist=True)
        if not parent.is_dir():
            raise PolicyError("parent directory does not exist")
        if path.exists() and not overwrite:
            raise PolicyError("target already exists; set overwrite=true explicitly")
        if path.exists() and path.is_dir():
            raise PolicyError("target is a directory")
        import tempfile
        fd, tmp_name = tempfile.mkstemp(prefix=".gpthands-", dir=parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)


def _safe_env() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_COLOR": "1"}


def _require_str(args: dict[str, Any], key: str, *, allow_empty: bool = False) -> str:
    value = args.get(key)
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f"{key} must be a {'string' if allow_empty else 'non-empty string'}")
    return value


def _relative(root: Path, path: Path) -> str:
    rel = path.resolve(strict=False).relative_to(root)
    return str(rel) if str(rel) else "."


def _action_hash(name: str, payload: dict[str, Any]) -> str:
    raw = json.dumps({"name": name, "payload": payload}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _state_root() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "gpthands"


def _default_audit_path() -> Path:
    return _state_root() / "audit.jsonl"


def _default_approval_key_path() -> Path:
    return _state_root() / "approval.key"


def serve_stdio(server: GPTHandsServer) -> int:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            message = json.loads(raw)
            if not isinstance(message, dict):
                raise ValueError("JSON-RPC message must be an object")
            response = server.handle(message)
        except (json.JSONDecodeError, ValueError) as exc:
            response = _rpc_error(None, -32700, redact_text(str(exc)))
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


def _write_policy(path: Path, data: dict[str, Any], workspace: Path) -> None:
    path = path.expanduser().resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    root = workspace.resolve(strict=True)
    try:
        if os.path.commonpath((str(root), str(path))) == str(root):
            raise PolicyError("policy authority must live outside workspace")
    except ValueError:
        pass
    encoded = json.dumps(data, indent=2, sort_keys=True) + "\n"
    flags = os.O_CREAT | os.O_TRUNC | os.O_WRONLY
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, encoded.encode("utf-8"))
        os.fsync(fd)
        if os.name != "nt":
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _lease_iso(seconds: int) -> str:
    return datetime.fromtimestamp(time.time() + seconds, tz=timezone.utc).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="GPTHands secure local MCP server")
    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="serve MCP over stdio")
    serve_p.add_argument("--workspace", type=Path, default=Path.cwd())
    serve_p.add_argument("--policy", type=Path)
    serve_p.add_argument("--audit-log", type=Path, default=_default_audit_path())

    path_p = sub.add_parser("policy-path", help="print the external policy path for a workspace")
    path_p.add_argument("--workspace", type=Path, default=Path.cwd())

    init_p = sub.add_parser("init-policy", help="create/replace an external lease-bound policy")
    init_p.add_argument("--workspace", type=Path, default=Path.cwd())
    init_p.add_argument("--lease-seconds", type=int, default=900)
    init_p.add_argument("--allow-write", action="store_true")
    init_p.add_argument("--allow-process", action="store_true")
    init_p.add_argument("--allow-network", action="store_true")
    init_p.add_argument("--command", action="append", default=[])
    init_p.add_argument("--approval-from", default="NETWORK")
    init_p.add_argument("--no-require-os-sandbox", action="store_true")

    approve_p = sub.add_parser("approve", help="issue a short-lived human approval token")
    approve_p.add_argument("--workspace", type=Path, default=Path.cwd())
    approve_p.add_argument("--risk", required=True, choices=[r.name for r in RiskLevel])
    approve_p.add_argument("--seconds", type=int, default=300)
    approve_p.add_argument("--action-hash")

    args = parser.parse_args()
    command = args.command or "serve"

    if command == "policy-path":
        print(default_policy_path(args.workspace.resolve(strict=True)))
        return 0
    if command == "init-policy":
        if not 1 <= args.lease_seconds <= 86400:
            print("lease-seconds must be between 1 and 86400", file=sys.stderr)
            return 2
        try:
            risk = RiskLevel.parse(args.approval_from)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        workspace = args.workspace.resolve(strict=True)
        expiry = _lease_iso(args.lease_seconds)
        data = {
            "allow_write": bool(args.allow_write),
            "allow_process": bool(args.allow_process),
            "allow_network_commands": bool(args.allow_network),
            "write_lease_until": expiry if args.allow_write else None,
            "process_lease_until": expiry if args.allow_process else None,
            "network_lease_until": expiry if args.allow_network else None,
            "allowed_commands": args.command,
            "approval_required_from": risk.name,
            "require_os_sandbox": not args.no_require_os_sandbox,
        }
        path = default_policy_path(workspace)
        _write_policy(path, data, workspace)
        print(path)
        return 0
    if command == "approve":
        try:
            manager = ApprovalManager(_default_approval_key_path())
            token = manager.issue(workspace=args.workspace.resolve(strict=True), risk=RiskLevel.parse(args.risk), ttl_seconds=args.seconds, action_hash=args.action_hash)
        except (ApprovalError, ValueError, OSError) as exc:
            print(f"approval refused: {exc}", file=sys.stderr)
            return 2
        print(token)
        return 0

    workspace = args.workspace.resolve(strict=True)
    try:
        policy = Policy.load(workspace, getattr(args, "policy", None))
        audit = AuditLogger(args.audit_log, workspace=policy.workspace)
        approvals = ApprovalManager(_default_approval_key_path())
    except (PolicyError, ApprovalError, OSError) as exc:
        print(f"GPTHands startup refused: {exc}", file=sys.stderr)
        return 2
    try:
        return serve_stdio(GPTHandsServer(policy, audit, approvals=approvals))
    finally:
        audit.close()


if __name__ == "__main__":
    raise SystemExit(main())
