from __future__ import annotations

import json
import threading
import time
from collections import deque
from contextlib import contextmanager
from typing import Any, Iterator

from .server import GPTHandsServer


class LimitError(RuntimeError):
    pass


class ActionLimiter:
    """Thread-safe sliding-window rate limit plus bounded concurrency."""

    def __init__(self, *, requests_per_minute: int, max_concurrent: int, queue_seconds: int) -> None:
        if requests_per_minute < 1 or max_concurrent < 1 or queue_seconds < 0:
            raise ValueError("invalid limiter settings")
        self.requests_per_minute = requests_per_minute
        self.max_concurrent = max_concurrent
        self.queue_seconds = queue_seconds
        self._times: deque[float] = deque()
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def _reserve_rate(self) -> None:
        now = time.monotonic()
        cutoff = now - 60.0
        with self._lock:
            while self._times and self._times[0] <= cutoff:
                self._times.popleft()
            if len(self._times) >= self.requests_per_minute:
                raise LimitError("tool request rate limit exceeded")
            self._times.append(now)

    @contextmanager
    def action(self) -> Iterator[None]:
        self._reserve_rate()
        acquired = self._slots.acquire(timeout=float(self.queue_seconds))
        if not acquired:
            raise LimitError("maximum concurrent tool actions reached")
        try:
            yield
        finally:
            self._slots.release()


class V03GPTHandsServer(GPTHandsServer):
    """v0.3 production wrapper adding quotas without weakening the v0.2 core."""

    VERSION = "0.3.0"

    def __init__(self, *args: Any, limiter: ActionLimiter | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.limiter = limiter or ActionLimiter(
            requests_per_minute=self.policy.max_requests_per_minute,
            max_concurrent=self.policy.max_concurrent_actions,
            queue_seconds=self.policy.max_queue_seconds,
        )

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        request_id = message.get("id") if isinstance(message, dict) else None
        method = message.get("method", "") if isinstance(message, dict) else ""
        try:
            if method == "tools/call" and request_id is not None:
                with self.limiter.action():
                    response = super().handle(message)
            else:
                response = super().handle(message)
        except LimitError as exc:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32001, "message": str(exc)},
            }

        if response is not None and method == "initialize" and isinstance(response.get("result"), dict):
            result = response["result"]
            server_info = result.get("serverInfo")
            if isinstance(server_info, dict):
                server_info["version"] = self.VERSION
            result["instructions"] = (
                "GPTHands v0.3 keeps authority outside repository content, verifies a tamper-evident audit chain, "
                "atomically consumes approval tokens across processes, enforces quotas, and retains v0.2 OS sandboxing."
            )
        return response

    def _workspace_info(self) -> tuple[str, dict[str, Any]]:
        payload = {
            "workspace": str(self.policy.workspace),
            "policy_path": str(self.policy.policy_path),
            "policy_schema_version": self.policy.schema_version,
            "server_version": self.VERSION,
            "allow_write": self.policy.allow_write,
            "allow_process": self.policy.allow_process,
            "allow_network_commands": self.policy.allow_network_commands,
            "require_os_sandbox": self.policy.require_os_sandbox,
            "approval_required_from": self.policy.approval_required_from.name,
            "allowed_commands": list(self.policy.allowed_commands),
            "limits": {
                "requests_per_minute": self.policy.max_requests_per_minute,
                "max_concurrent_actions": self.policy.max_concurrent_actions,
                "max_queue_seconds": self.policy.max_queue_seconds,
            },
            "leases": {
                "write_until": self.policy.write_lease_until,
                "process_until": self.policy.process_lease_until,
                "network_until": self.policy.network_lease_until,
            },
        }
        return json.dumps(payload, indent=2), {"capabilities_only": True, "risk": "READ"}
