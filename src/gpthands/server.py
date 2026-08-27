from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .audit import AuditLogger, content_fingerprint, redact_text
from .policy import Policy, PolicyError

SERVER_NAME = "GPTHands"
SERVER_VERSION = "0.1.0"
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
    _tool("workspace_info", "Return the active workspace and effective local capabilities.", {}, [], read_only=True),
    _tool(
        "read_file",
        "Read a UTF-8 text file inside the workspace. Secret-like paths are denied and detected secret values are redacted.",
        {"target": {"type": "string"}},
        ["target"],
        read_only=True,
    ),
    _tool(
        "list_dir",
        "List one directory inside the workspace.",
        {"target": {"type": "string", "default": "."}},
        [],
        read_only=True,
    ),
    _tool(
        "grep",
        "Search text files below a workspace path. Results are bounded and secret-like files are skipped.",
        {
            "pattern": {"type": "string"},
            "target": {"type": "string", "default": "."},
            "regex": {"type": "boolean", "default": False},
        },
        ["pattern"],
        read_only=True,
    ),
    _tool(
        "write_file",
        "Create or replace one UTF-8 file inside the workspace. Disabled unless local policy enables write capability.",
        {
            "target": {"type": "string"},
            "content": {"type": "string"},
            "overwrite": {"type": "boolean", "default": False},
        },
        ["target", "content"],
        read_only=False,
    ),
    _tool(
        "run_command",
        "Run an argv array without a shell. Disabled unless local policy enables process capability and allowlists the executable.",
        {
            "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "cwd": {"type": "string", "default": "."},
        },
        ["argv"],
        read_only=False,
    ),
]


class GPTHandsServer:
    def __init__(self, policy: Policy, audit: AuditLogger) -> None:
        self.policy = policy
        self.audit = audit

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
                        "GPTHands is security-first. Local policy, not prompt or repository content, grants authority. "
                        "Call workspace_info first. Write/process capabilities may be disabled."
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
        except (PolicyError, ValueError, OSError) as exc:
            return _rpc_error(request_id, -32000, redact_text(str(exc)))
        except Exception as exc:  # defensive boundary: do not crash MCP loop
            return _rpc_error(request_id, -32603, f"internal error: {type(exc).__name__}")

    def _call_tool(self, request_id: Any, name: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            if name == "workspace_info":
                text = json.dumps(
                    {
                        "workspace": str(self.policy.workspace),
                        "allow_write": self.policy.allow_write,
                        "allow_process": self.policy.allow_process,
                        "allow_network_commands": self.policy.allow_network_commands,
                        "allowed_commands": list(self.policy.allowed_commands),
                    },
                    indent=2,
                )
                detail = {"capabilities_only": True}
            elif name == "read_file":
                text, detail = self._read_file(args)
            elif name == "list_dir":
                text, detail = self._list_dir(args)
            elif name == "grep":
                text, detail = self._grep(args)
            elif name == "write_file":
                text, detail = self._write_file(args)
            elif name == "run_command":
                text, detail = self._run_command(args)
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
            return {
                "content": [{"type": "text", "text": redact_text(str(exc))}],
                "isError": True,
            }

    def _read_file(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        target = _require_str(args, "target")
        path = self.policy.resolve_path(target, must_exist=True)
        if not path.is_file():
            raise PolicyError("target is not a file")
        size = path.stat().st_size
        if size > self.policy.max_read_bytes:
            raise PolicyError(f"file exceeds max_read_bytes ({size} > {self.policy.max_read_bytes})")
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError("binary/non-UTF-8 files are not readable in v0.1") from exc
        return text, {"target": _relative(self.policy.workspace, path), "bytes": len(data)}

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
            kind = "dir" if child.is_dir() else "file"
            rows.append(f"{kind}\t{child.name}")
        return "\n".join(rows), {"target": _relative(self.policy.workspace, path), "entries": len(rows)}

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
            if len(results) >= 200 or scanned >= 5000:
                break
            if not path.is_file():
                continue
            try:
                rel = _relative(self.policy.workspace, path)
                safe = self.policy.resolve_path(rel, must_exist=True)
            except (PolicyError, OSError):
                continue
            try:
                if safe.stat().st_size > min(self.policy.max_read_bytes, 2_000_000):
                    continue
                text = safe.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            scanned += 1
            for line_no, line in enumerate(text.splitlines(), 1):
                matched = bool(matcher.search(line)) if matcher else pattern in line
                if matched:
                    results.append(f"{rel}:{line_no}:{redact_text(line)}")
                    if len(results) >= 200:
                        break
        return "\n".join(results), {"target": target, "files_scanned": scanned, "matches": len(results)}

    def _write_file(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        self.policy.require_write()
        target = _require_str(args, "target")
        content = _require_str(args, "content", allow_empty=True)
        overwrite = args.get("overwrite", False)
        if not isinstance(overwrite, bool):
            raise ValueError("overwrite must be boolean")
        data = content.encode("utf-8")
        if len(data) > self.policy.max_write_bytes:
            raise PolicyError("content exceeds max_write_bytes")

        path = self.policy.resolve_path(target, must_exist=False)
        parent = self.policy.resolve_path(_relative(self.policy.workspace, path.parent), must_exist=True)
        if not parent.is_dir():
            raise PolicyError("parent directory does not exist")
        if path.exists() and not overwrite:
            raise PolicyError("target already exists; set overwrite=true explicitly")
        if path.exists() and path.is_dir():
            raise PolicyError("target is a directory")

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
        return "written", {"target": target, "overwrite": overwrite, "content": content_fingerprint(content)}

    def _run_command(self, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        argv = args.get("argv")
        if not isinstance(argv, list):
            raise ValueError("argv must be an array")
        checked = self.policy.validate_command(argv)
        cwd_value = args.get("cwd", ".")
        if not isinstance(cwd_value, str):
            raise ValueError("cwd must be a string")
        cwd = self.policy.resolve_path(cwd_value, must_exist=True)
        if not cwd.is_dir():
            raise PolicyError("cwd is not a directory")

        with tempfile.TemporaryDirectory(prefix="gpthands-home-") as isolated_home:
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": isolated_home,
                "TMPDIR": isolated_home,
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "NO_COLOR": "1",
            }
            try:
                completed = subprocess.run(
                    checked,
                    cwd=cwd,
                    env=env,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=self.policy.max_command_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise PolicyError(f"command exceeded {self.policy.max_command_seconds}s timeout") from exc

        output = completed.stdout[: self.policy.max_output_bytes].decode("utf-8", errors="replace")
        if len(completed.stdout) > self.policy.max_output_bytes:
            output += "\n[output truncated by GPTHands policy]"
        detail = {
            "program": Path(checked[0]).name,
            "argc": len(checked),
            "cwd": _relative(self.policy.workspace, cwd),
            "exit_code": completed.returncode,
            "output_bytes": min(len(completed.stdout), self.policy.max_output_bytes),
        }
        return f"exit_code={completed.returncode}\n{output}", detail


def _require_str(args: dict[str, Any], key: str, *, allow_empty: bool = False) -> str:
    value = args.get(key)
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f"{key} must be a {'string' if allow_empty else 'non-empty string'}")
    return value


def _relative(root: Path, path: Path) -> str:
    rel = path.resolve(strict=False).relative_to(root)
    return str(rel) if str(rel) else "."


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _default_audit_path() -> Path:
    state = os.environ.get("XDG_STATE_HOME")
    if state:
        return Path(state) / "gpthands" / "audit.jsonl"
    return Path.home() / ".local" / "state" / "gpthands" / "audit.jsonl"


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


def main() -> int:
    parser = argparse.ArgumentParser(description="GPTHands secure local MCP server")
    parser.add_argument("--workspace", type=Path, default=Path.cwd(), help="workspace root (default: current directory)")
    parser.add_argument("--audit-log", type=Path, default=_default_audit_path(), help="append-only JSONL audit log path")
    args = parser.parse_args()

    try:
        policy = Policy.load(args.workspace)
        audit = AuditLogger(args.audit_log, workspace=policy.workspace)
    except (PolicyError, OSError) as exc:
        print(f"GPTHands startup refused: {exc}", file=sys.stderr)
        return 2

    try:
        return serve_stdio(GPTHandsServer(policy, audit))
    finally:
        audit.close()


if __name__ == "__main__":
    raise SystemExit(main())
