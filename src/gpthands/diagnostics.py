from __future__ import annotations

import json
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from .audit import verify_audit_file
from .credentials import CredentialStore, CredentialStoreError
from .policy import Policy, PolicyError, default_policy_path
from .sandbox import SandboxError, SandboxRunner
from .state import state_root
from .trust import TrustError, WorkspaceTrustStore


@dataclass(frozen=True)
class DiagnosticCheck:
    name: str
    status: str
    detail: str


def _check(name: str, fn) -> DiagnosticCheck:
    try:
        detail = fn()
        return DiagnosticCheck(name, "ok", str(detail))
    except Exception as exc:
        return DiagnosticCheck(name, "error", f"{type(exc).__name__}: {exc}")


def diagnostic_report(workspace: Path) -> dict:
    resolved = workspace.expanduser().resolve(strict=True)
    audit_path = state_root() / "audit.jsonl"

    def policy_check() -> str:
        path = default_policy_path(resolved)
        if not path.exists():
            return f"not initialized ({path})"
        policy = Policy.load(resolved, path)
        return f"schema={policy.schema_version}; os_sandbox={policy.require_os_sandbox}"

    def sandbox_check() -> str:
        runner = SandboxRunner(require_os_sandbox=True)
        command = [sys.executable, "-c", "pass"]
        plan = runner.plan(
            command=command,
            workspace=resolved,
            cwd=resolved,
            allow_write=False,
            allow_network=False,
            isolated_home=state_root(),
        )
        return plan.backend

    def audit_check() -> str:
        if not audit_path.exists():
            return "no audit log yet"
        result = verify_audit_file(audit_path)
        if not result.valid:
            raise RuntimeError(result.error or "audit chain invalid")
        return f"valid; chained_records={result.chained_records}"

    def trust_check() -> str:
        return "trusted" if WorkspaceTrustStore().is_trusted(resolved) else "not trusted"

    def credentials_check() -> str:
        return CredentialStore().backend()

    def tunnel_check() -> str:
        binary = shutil.which("tunnel-client")
        if not binary:
            raise RuntimeError("official tunnel-client not found on PATH")
        return binary

    checks = [
        DiagnosticCheck("python", "ok", platform.python_version()),
        DiagnosticCheck("platform", "ok", platform.platform()),
        DiagnosticCheck("workspace", "ok", str(resolved)),
        _check("workspace_trust", trust_check),
        _check("policy", policy_check),
        _check("os_sandbox", sandbox_check),
        _check("audit_chain", audit_check),
        _check("credential_store", credentials_check),
        _check("secure_mcp_tunnel", tunnel_check),
    ]
    hard_errors = [c for c in checks if c.status == "error" and c.name in {"workspace", "os_sandbox", "audit_chain"}]
    return {
        "ok": not hard_errors,
        "workspace": str(resolved),
        "state_root": str(state_root()),
        "checks": [asdict(c) for c in checks],
    }


def diagnostic_json(workspace: Path) -> str:
    return json.dumps(diagnostic_report(workspace), indent=2, ensure_ascii=False)
