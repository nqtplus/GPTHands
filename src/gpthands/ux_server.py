from __future__ import annotations

import json
from typing import Any

from .limits import V03GPTHandsServer
from .notifications import notify_approval_required
from .risk import RiskLevel
from .trust import WorkspaceTrustStore


class V04GPTHandsServer(V03GPTHandsServer):
    """v0.4 wrapper: exposes trust state and surfaces approval requests locally."""

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

    def _require_approval(self, token: object, *, risk: RiskLevel, action_hash: str) -> None:
        if token is None and self.policy.approval_required(risk):
            notify_approval_required(workspace=self.policy.workspace, risk=risk.name, action_hash=action_hash)
        super()._require_approval(token, risk=risk, action_hash=action_hash)
