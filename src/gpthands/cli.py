from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .approval import ApprovalError, ApprovalManager
from .audit import AuditLogger, verify_audit_file
from .limits import V03GPTHandsServer
from .policy import POLICY_SCHEMA_VERSION, Policy, PolicyError, default_policy_path, migrate_policy_data
from .risk import RiskLevel
from .server import serve_stdio


def state_root() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "gpthands"


def default_audit_path() -> Path:
    return state_root() / "audit.jsonl"


def default_approval_key_path() -> Path:
    return state_root() / "approval.key"


def _inside(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath((str(root), str(candidate))) == str(root)
    except ValueError:
        return False


def _secure_write_policy(path: Path, data: dict, workspace: Path) -> None:
    workspace = workspace.resolve(strict=True)
    lexical = Path(os.path.abspath(path.expanduser()))
    if lexical.is_symlink():
        raise PolicyError("refusing to replace a symlink policy path")
    parent = lexical.parent.resolve(strict=False)
    target = parent / lexical.name
    if _inside(workspace, target):
        raise PolicyError("policy authority must live outside workspace")
    parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(parent, 0o700)

    encoded = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=".gpthands-policy-", dir=parent)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
        if os.name != "nt":
            os.chmod(target, 0o600)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _lease_iso(seconds: int) -> str:
    return datetime.fromtimestamp(time.time() + seconds, tz=timezone.utc).isoformat()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GPTHands secure local MCP bridge")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    serve = sub.add_parser("serve", help="serve MCP over stdio")
    serve.add_argument("--workspace", type=Path, default=Path.cwd())
    serve.add_argument("--policy", type=Path)
    serve.add_argument("--audit-log", type=Path, default=default_audit_path())

    path = sub.add_parser("policy-path", help="print the external policy path")
    path.add_argument("--workspace", type=Path, default=Path.cwd())

    init = sub.add_parser("init-policy", help="create a lease-bound external policy")
    init.add_argument("--workspace", type=Path, default=Path.cwd())
    init.add_argument("--lease-seconds", type=int, default=900)
    init.add_argument("--allow-write", action="store_true")
    init.add_argument("--allow-process", action="store_true")
    init.add_argument("--allow-network", action="store_true")
    init.add_argument("--command", dest="allowed_commands", action="append", default=[])
    init.add_argument("--approval-from", choices=[r.name for r in RiskLevel], default="EXEC")
    init.add_argument("--no-require-os-sandbox", action="store_true")
    init.add_argument("--max-requests-per-minute", type=int, default=120)
    init.add_argument("--max-concurrent-actions", type=int, default=4)
    init.add_argument("--max-queue-seconds", type=int, default=2)

    migrate = sub.add_parser("migrate-policy", help="rewrite a supported historical policy to the current schema")
    migrate.add_argument("--workspace", type=Path, default=Path.cwd())
    migrate.add_argument("--policy", type=Path)

    approve = sub.add_parser("approve", help="issue a short-lived one-time human approval token")
    approve.add_argument("--workspace", type=Path, default=Path.cwd())
    approve.add_argument("--risk", required=True, choices=[r.name for r in RiskLevel])
    approve.add_argument("--seconds", type=int, default=300)
    approve.add_argument("--action-hash")

    audit = sub.add_parser("audit-verify", help="verify the tamper-evident audit chain")
    audit.add_argument("--audit-log", type=Path, default=default_audit_path())
    return parser


def main(argv: list[str] | None = None) -> int:
    args_in = list(sys.argv[1:] if argv is None else argv)
    known = {"serve", "policy-path", "init-policy", "migrate-policy", "approve", "audit-verify"}
    if not args_in or args_in[0] not in known:
        args_in.insert(0, "serve")
    args = _build_parser().parse_args(args_in)

    if args.subcommand == "policy-path":
        try:
            print(default_policy_path(args.workspace.resolve(strict=True)))
        except OSError as exc:
            print(f"policy-path failed: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.subcommand == "audit-verify":
        result = verify_audit_file(args.audit_log)
        print(json.dumps({
            "valid": result.valid,
            "anchored": result.anchored,
            "chained_records": result.chained_records,
            "legacy_records": result.legacy_records,
            "last_hash": result.last_hash,
            "error": result.error,
        }, indent=2))
        return 0 if result.valid else 2

    if args.subcommand == "init-policy":
        if not 1 <= args.lease_seconds <= 86_400:
            print("lease-seconds must be between 1 and 86400", file=sys.stderr)
            return 2
        if args.allow_network and not args.allow_process:
            print("--allow-network requires --allow-process", file=sys.stderr)
            return 2
        if not 1 <= args.max_requests_per_minute <= 6000:
            print("max-requests-per-minute must be between 1 and 6000", file=sys.stderr)
            return 2
        if not 1 <= args.max_concurrent_actions <= 64:
            print("max-concurrent-actions must be between 1 and 64", file=sys.stderr)
            return 2
        if not 0 <= args.max_queue_seconds <= 30:
            print("max-queue-seconds must be between 0 and 30", file=sys.stderr)
            return 2
        try:
            workspace = args.workspace.resolve(strict=True)
            expiry = _lease_iso(args.lease_seconds)
            data = {
                "schema_version": POLICY_SCHEMA_VERSION,
                "allow_write": bool(args.allow_write),
                "allow_process": bool(args.allow_process),
                "allow_network_commands": bool(args.allow_network),
                "write_lease_until": expiry if args.allow_write else None,
                "process_lease_until": expiry if args.allow_process else None,
                "network_lease_until": expiry if args.allow_network else None,
                "allowed_commands": args.allowed_commands,
                "approval_required_from": args.approval_from,
                "require_os_sandbox": not args.no_require_os_sandbox,
                "max_requests_per_minute": args.max_requests_per_minute,
                "max_concurrent_actions": args.max_concurrent_actions,
                "max_queue_seconds": args.max_queue_seconds,
            }
            target = default_policy_path(workspace)
            _secure_write_policy(target, data, workspace)
            print(target)
        except (PolicyError, OSError) as exc:
            print(f"init-policy refused: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.subcommand == "migrate-policy":
        try:
            workspace = args.workspace.resolve(strict=True)
            target = args.policy or default_policy_path(workspace)
            if not target.exists():
                raise PolicyError(f"policy does not exist: {target}")
            if target.is_symlink():
                raise PolicyError("policy file must not be a symlink")
            raw = json.loads(target.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise PolicyError("policy root must be an object")
            migrated = migrate_policy_data(raw)
            _secure_write_policy(target, migrated, workspace)
            Policy.load(workspace, target)
            print(target)
        except (PolicyError, OSError, json.JSONDecodeError) as exc:
            print(f"migrate-policy refused: {exc}", file=sys.stderr)
            return 2
        return 0

    if args.subcommand == "approve":
        try:
            workspace = args.workspace.resolve(strict=True)
            manager = ApprovalManager(default_approval_key_path())
            try:
                token = manager.issue(
                    workspace=workspace,
                    risk=RiskLevel.parse(args.risk),
                    ttl_seconds=args.seconds,
                    action_hash=args.action_hash,
                )
            finally:
                manager.close()
            print(token)
        except (ApprovalError, ValueError, OSError) as exc:
            print(f"approval refused: {exc}", file=sys.stderr)
            return 2
        return 0

    approvals: ApprovalManager | None = None
    audit: AuditLogger | None = None
    try:
        workspace = args.workspace.resolve(strict=True)
        policy = Policy.load(workspace, args.policy)
        audit = AuditLogger(args.audit_log, workspace=workspace)
        approvals = ApprovalManager(default_approval_key_path())
    except (PolicyError, ApprovalError, OSError) as exc:
        if audit is not None:
            audit.close()
        if approvals is not None:
            approvals.close()
        print(f"GPTHands startup refused: {exc}", file=sys.stderr)
        return 2
    try:
        return serve_stdio(V03GPTHandsServer(policy, audit, approvals=approvals))
    finally:
        audit.close()
        approvals.close()


if __name__ == "__main__":
    raise SystemExit(main())
