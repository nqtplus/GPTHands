from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .approval import ApprovalError, ApprovalManager
from .audit import AuditLogger, verify_audit_file
from .control_ui import serve_control_ui
from .credentials import CredentialStore, CredentialStoreError
from .diagnostics import diagnostic_json
from .installer import InstallError, UserInstaller
from .policy import POLICY_SCHEMA_VERSION, Policy, PolicyError, default_policy_path, migrate_policy_data
from .risk import RiskLevel
from .stable_server import V10GPTHandsServer, serve_stdio_bounded
from .state import state_root
from .trust import TrustError, WorkspaceTrustStore
from .tunnel import TunnelError, build_tunnel_plan, execute_tunnel_step


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


def _workspace_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", type=Path, default=Path.cwd())


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GPTHands stable secure local MCP bridge")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    serve = sub.add_parser("serve", help="serve MCP over bounded stdio (2026-07-28 + legacy 2025-06-18)")
    _workspace_arg(serve)
    serve.add_argument("--policy", type=Path)
    serve.add_argument("--audit-log", type=Path, default=default_audit_path())
    serve.add_argument("--allow-untrusted", action="store_true", help="explicit compatibility override; not recommended")

    path = sub.add_parser("policy-path", help="print the external policy path")
    _workspace_arg(path)

    init = sub.add_parser("init-policy", help="create a lease-bound external policy")
    _workspace_arg(init)
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
    _workspace_arg(migrate)
    migrate.add_argument("--policy", type=Path)

    approve = sub.add_parser("approve", help="issue a short-lived one-time exact-action human approval token")
    _workspace_arg(approve)
    approve.add_argument("--risk", required=True, choices=[r.name for r in RiskLevel])
    approve.add_argument("--seconds", type=int, default=300)
    approve.add_argument("--action-hash", required=True, help="exact pending action SHA-256 shown by GPTHands")

    audit = sub.add_parser("audit-verify", help="verify the tamper-evident audit chain")
    audit.add_argument("--audit-log", type=Path, default=default_audit_path())

    trust = sub.add_parser("trust", help="explicitly trust one canonical workspace")
    _workspace_arg(trust)
    trust.add_argument("--label")
    untrust = sub.add_parser("untrust", help="remove workspace trust")
    _workspace_arg(untrust)
    sub.add_parser("trust-list", help="list explicitly trusted workspaces")

    sub.add_parser("credential-backend", help="show the OS credential-store backend")
    cred_set = sub.add_parser("credential-set", help="store a secret in the OS credential store")
    cred_set.add_argument("name")
    cred_set.add_argument("--stdin", action="store_true", help="read the secret from stdin")
    cred_del = sub.add_parser("credential-delete", help="delete a secret from the OS credential store")
    cred_del.add_argument("name")

    doctor = sub.add_parser("doctor", help="run local health and security diagnostics")
    _workspace_arg(doctor)

    ui = sub.add_parser("ui", help="start loopback-only local status/config UI")
    _workspace_arg(ui)
    ui.add_argument("--port", type=int, default=0)
    ui.add_argument("--no-browser", action="store_true")

    for name, help_text in (
        ("tunnel-plan", "print a Secure MCP Tunnel setup plan"),
        ("tunnel-init", "create/update a tunnel-client profile via the official client"),
        ("tunnel-doctor", "run official tunnel-client doctor"),
        ("tunnel-run", "run the official Secure MCP Tunnel client"),
    ):
        p = sub.add_parser(name, help=help_text)
        _workspace_arg(p)
        p.add_argument("--tunnel-id", required=True)
        p.add_argument("--profile", default="gpthands")
        p.add_argument("--tunnel-client")
        if name != "tunnel-plan":
            p.add_argument("--credential-name", help="OS credential-store entry injected as CONTROL_PLANE_API_KEY")

    install = sub.add_parser("install-user", help="install local GPTHands UX launchers with rollback metadata")
    install.add_argument("--bin-dir", type=Path)
    uninstall = sub.add_parser("uninstall-user", help="remove GPTHands UX launchers and restore backups")
    uninstall.add_argument("--bin-dir", type=Path)
    return parser


def _tunnel_plan_from_args(args):
    return build_tunnel_plan(workspace=args.workspace, tunnel_id=args.tunnel_id, profile=args.profile, binary=args.tunnel_client)


def main(argv: list[str] | None = None) -> int:
    args_in = list(sys.argv[1:] if argv is None else argv)
    known = {
        "serve", "policy-path", "init-policy", "migrate-policy", "approve", "audit-verify",
        "trust", "untrust", "trust-list", "credential-backend", "credential-set", "credential-delete",
        "doctor", "ui", "tunnel-plan", "tunnel-init", "tunnel-doctor", "tunnel-run",
        "install-user", "uninstall-user",
    }
    if not args_in or args_in[0] not in known:
        args_in.insert(0, "serve")
    args = _build_parser().parse_args(args_in)

    try:
        if args.subcommand == "policy-path":
            print(default_policy_path(args.workspace.resolve(strict=True)))
            return 0

        if args.subcommand == "audit-verify":
            result = verify_audit_file(args.audit_log)
            print(json.dumps({
                "valid": result.valid, "anchored": result.anchored,
                "chained_records": result.chained_records, "legacy_records": result.legacy_records,
                "last_hash": result.last_hash, "error": result.error,
            }, indent=2))
            return 0 if result.valid else 2

        if args.subcommand == "trust":
            print(json.dumps(WorkspaceTrustStore().trust(args.workspace, label=args.label), indent=2, ensure_ascii=False))
            return 0
        if args.subcommand == "untrust":
            print("removed" if WorkspaceTrustStore().untrust(args.workspace) else "not-trusted")
            return 0
        if args.subcommand == "trust-list":
            print(json.dumps(WorkspaceTrustStore().list(), indent=2, ensure_ascii=False))
            return 0

        if args.subcommand == "credential-backend":
            print(CredentialStore().backend())
            return 0
        if args.subcommand == "credential-set":
            value = sys.stdin.read().rstrip("\r\n") if args.stdin else getpass.getpass("Secret: ")
            CredentialStore().set(args.name, value)
            print("stored")
            return 0
        if args.subcommand == "credential-delete":
            print("deleted" if CredentialStore().delete(args.name) else "not-found")
            return 0

        if args.subcommand == "doctor":
            print(diagnostic_json(args.workspace))
            return 0
        if args.subcommand == "ui":
            return serve_control_ui(args.workspace, port=args.port, open_browser=not args.no_browser)

        if args.subcommand.startswith("tunnel-"):
            plan = _tunnel_plan_from_args(args)
            if args.subcommand == "tunnel-plan":
                print(json.dumps({
                    "profile": plan.profile, "init": plan.init_argv, "doctor": plan.doctor_argv, "run": plan.run_argv,
                    "secret_model": "CONTROL_PLANE_API_KEY is an env reference; literal keys are not written to the profile",
                }, indent=2))
                return 0
            argv_value = {"tunnel-init": plan.init_argv, "tunnel-doctor": plan.doctor_argv, "tunnel-run": plan.run_argv}[args.subcommand]
            completed = execute_tunnel_step(argv_value, credential_name=args.credential_name, timeout=120 if args.subcommand == "tunnel-run" else 60)
            sys.stdout.write(completed.stdout)
            return completed.returncode

        if args.subcommand == "install-user":
            print(json.dumps(UserInstaller(bin_dir=args.bin_dir).install(), indent=2))
            return 0
        if args.subcommand == "uninstall-user":
            print(json.dumps(UserInstaller(bin_dir=args.bin_dir).uninstall(), indent=2))
            return 0

        if args.subcommand == "init-policy":
            if not 1 <= args.lease_seconds <= 86_400:
                raise ValueError("lease-seconds must be between 1 and 86400")
            if args.allow_network and not args.allow_process:
                raise ValueError("--allow-network requires --allow-process")
            if not 1 <= args.max_requests_per_minute <= 6000:
                raise ValueError("max-requests-per-minute must be between 1 and 6000")
            if not 1 <= args.max_concurrent_actions <= 64:
                raise ValueError("max-concurrent-actions must be between 1 and 64")
            if not 0 <= args.max_queue_seconds <= 30:
                raise ValueError("max-queue-seconds must be between 0 and 30")
            workspace = args.workspace.resolve(strict=True)
            expiry = _lease_iso(args.lease_seconds)
            data = {
                "schema_version": POLICY_SCHEMA_VERSION,
                "allow_write": bool(args.allow_write), "allow_process": bool(args.allow_process),
                "allow_network_commands": bool(args.allow_network),
                "write_lease_until": expiry if args.allow_write else None,
                "process_lease_until": expiry if args.allow_process else None,
                "network_lease_until": expiry if args.allow_network else None,
                "allowed_commands": args.allowed_commands, "approval_required_from": args.approval_from,
                "require_os_sandbox": not args.no_require_os_sandbox,
                "max_requests_per_minute": args.max_requests_per_minute,
                "max_concurrent_actions": args.max_concurrent_actions,
                "max_queue_seconds": args.max_queue_seconds,
            }
            target = default_policy_path(workspace)
            _secure_write_policy(target, data, workspace)
            print(target)
            return 0

        if args.subcommand == "migrate-policy":
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
            return 0

        if args.subcommand == "approve":
            workspace = args.workspace.resolve(strict=True)
            manager = ApprovalManager(default_approval_key_path())
            try:
                token = manager.issue(workspace=workspace, risk=RiskLevel.parse(args.risk), ttl_seconds=args.seconds, action_hash=args.action_hash)
            finally:
                manager.close()
            print(token)
            return 0

        workspace = args.workspace.resolve(strict=True)
        if not args.allow_untrusted and not WorkspaceTrustStore().is_trusted(workspace):
            print("GPTHands startup refused: workspace is not explicitly trusted; run `gpthands trust --workspace <path>` first", file=sys.stderr)
            return 2
        policy = Policy.load(workspace, args.policy)
        audit = AuditLogger(args.audit_log, workspace=workspace)
        approvals = ApprovalManager(default_approval_key_path())
        try:
            return serve_stdio_bounded(V10GPTHandsServer(policy, audit, approvals=approvals))
        finally:
            audit.close()
            approvals.close()

    except (PolicyError, ApprovalError, CredentialStoreError, TrustError, TunnelError, InstallError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"GPTHands refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
