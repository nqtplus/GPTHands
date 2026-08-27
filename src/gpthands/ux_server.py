from __future__ import annotations

import json
from typing import Any

from .limits import V03GPTHandsServer
from .notifications import notify_approval_required
from .pending_approvals import PendingApprovalStore
from .risk import RiskLevel
from .trust import WorkspaceTrustStore


class V04GPTHandsServer(V03GPTHandsServer):
    """v0.4 wrapper: explicit trust plus local action-bound approval UX."""

    VERSION = "0.4.0"

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        response = super().handle(message)
        if response is not None and message.get("method") == "initialize" and isinstance(response.get("result"), dict):
            result = response["result"]
            server_info = result.get("serverInfo")
            if isinstance(server_info, dict):
                server_info["version"] = self.VERSION
            result["instructions"] = (
                "GPTHands v0.4 keeps mutable authority outside repository content, exposes explicit workspace trust state, "
                "uses OS-backed credentials, action-bound approvals, OS sandboxing, tamper-evident audit, and Secure MCP Tunnel helpers."
            )
        return response

    def _workspace_info(self) -> tuple[str, dict[str, Any]]:
        text, detail = super()._workspace_info()
        payload = json.loads(text)
        payload["server_version"] = self.VERSION
        try:
            payload["workspace_trusted"] = WorkspaceTrustStore().is_trusted(self.policy.workspace)
        except Exception:
            payload["workspace_trusted"] = False
        return json.dumps(payload, indent=2), detail

    def _pending_add(self, risk: RiskLevel, action_hash: str) -> None:
        store = PendingApprovalStore()
        try:
            store.add(workspace=self.policy.workspace, risk=risk.name, action_hash=action_hash)
        except Exception:
            # The queue improves local UX only; approval enforcement below remains authoritative.
            pass
        finally:
            store.close()

    def _pending_remove(self, action_hash: str) -> None:
        store = PendingApprovalStore()
        try:
            store.remove(workspace=self.policy.workspace, action_hash=action_hash)
        except Exception:
            pass
        finally:
            store.close()

    def _require_approval(self, token: object, *, risk: RiskLevel, action_hash: str) -> None:
        required = self.policy.approval_required(risk)
        if token is None and required:
            self._pending_add(risk, action_hash)
            notify_approval_required(workspace=self.policy.workspace, risk=risk.name, action_hash=action_hash)
        super()._require_approval(token, risk=risk, action_hash=action_hash)
        if token is not None and required:
            self._pending_remove(action_hash)
