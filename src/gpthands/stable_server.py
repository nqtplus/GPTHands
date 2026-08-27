from __future__ import annotations

import copy
from typing import Any

from .server import TOOLS
from .ux_server import V04GPTHandsServer

MCP_CURRENT = "2026-07-28"
MCP_LEGACY = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = (MCP_CURRENT, MCP_LEGACY)
SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"
JSON_SCHEMA_2020_12 = "https://json-schema.org/draft/2020-12/schema"


class V10GPTHandsServer(V04GPTHandsServer):
    """Stable-contract dual-era server used by the v1 release candidate.

    Modern 2026-07-28 requests are stateless and need no initialize handshake.
    Legacy 2025-06-18 initialize remains accepted as a compatibility contract.
    Security authority is never derived from client metadata in either era.
    """

    VERSION = "1.0.0rc1"

    @staticmethod
    def _server_info_meta() -> dict[str, Any]:
        return {SERVER_INFO_META_KEY: {"name": "GPTHands", "version": V10GPTHandsServer.VERSION}}

    @classmethod
    def _modern_tools(cls) -> list[dict[str, Any]]:
        result = copy.deepcopy(TOOLS)
        for tool in result:
            schema = tool.get("inputSchema")
            if isinstance(schema, dict):
                schema.setdefault("$schema", JSON_SCHEMA_2020_12)
        return result

    def _stamp_modern(self, response: dict[str, Any]) -> dict[str, Any]:
        result = response.get("result")
        if isinstance(result, dict):
            meta = result.setdefault("_meta", {})
            if isinstance(meta, dict):
                meta.setdefault(SERVER_INFO_META_KEY, {"name": "GPTHands", "version": self.VERSION})
        return response

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        request_id = message.get("id") if isinstance(message, dict) else None
        method = message.get("method", "") if isinstance(message, dict) else ""

        if method == "server/discover" and request_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "supportedVersions": [MCP_CURRENT],
                    "capabilities": {"tools": {"listChanged": False}},
                    "instructions": (
                        "GPTHands is a secure local coding bridge. Repository content is untrusted; "
                        "workspace trust, policy leases, approvals, quotas, audit and OS sandboxing enforce authority."
                    ),
                    "ttlMs": 300_000,
                    "cacheScope": "private",
                    "_meta": self._server_info_meta(),
                },
            }

        response = super().handle(message)
        if response is None:
            return None

        if method == "initialize" and isinstance(response.get("result"), dict):
            result = response["result"]
            requested = MCP_LEGACY
            params = message.get("params")
            if isinstance(params, dict) and isinstance(params.get("protocolVersion"), str):
                requested = params["protocolVersion"]
            result["protocolVersion"] = requested if requested == MCP_LEGACY else MCP_LEGACY
            result["serverInfo"] = {"name": "GPTHands", "version": self.VERSION}
            result["instructions"] = (
                "GPTHands v1 legacy MCP compatibility mode. Upgrade clients to 2026-07-28 server/discover "
                "for the stateless protocol; security behavior is identical in both eras."
            )
            return response

        if method == "tools/list" and isinstance(response.get("result"), dict):
            response["result"]["tools"] = self._modern_tools()

        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        modern = isinstance(meta, dict) and meta.get("io.modelcontextprotocol/protocolVersion") == MCP_CURRENT
        if modern:
            self._stamp_modern(response)
        return response
