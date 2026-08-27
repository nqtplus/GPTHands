# GPTHands v1 MCP Compatibility Contract

GPTHands v1 supports two MCP eras on the same stdio server without using client identity as authorization input.

## Current protocol — `2026-07-28`

The modern path is the default compatibility target.

- `server/discover` is implemented and may be called before any other request.
- No `initialize` handshake is required for modern requests.
- `server/discover` advertises `2026-07-28`, tool capability, private cache hints, and GPTHands server identity in `_meta["io.modelcontextprotocol/serverInfo"]`.
- Modern requests may carry `_meta["io.modelcontextprotocol/protocolVersion"] = "2026-07-28"`.
- Modern responses are stamped with server identity metadata.
- Tool input schemas explicitly declare JSON Schema 2020-12.
- `tools/list` ordering is deterministic and `listChanged` is false for one process lifetime/version.
- GPTHands does not depend on session identifiers or server-to-client requests.

The stdio transport does not have HTTP routing headers. Secure MCP Tunnel is delegated to the official OpenAI `tunnel-client`, which owns its transport/control-plane behavior.

## Legacy protocol — `2025-06-18`

GPTHands v1 keeps the legacy `initialize` flow for older clients:

- an `initialize` request requesting `2025-06-18` receives `2025-06-18`;
- `serverInfo.version` reports the effective GPTHands package version;
- all v1 security controls are identical to the modern path.

An `initialize` request cannot negotiate `2026-07-28`; the modern revision is handshake-free and must use the modern request model.

## Security invariant

Client `_meta`, `clientInfo`, advertised capabilities, protocol revision and server discovery are compatibility data only. They never grant:

- workspace trust;
- file-write capability;
- process capability;
- network capability;
- human approval;
- credential access.

Those authorities remain owner-controlled and external to repository content.

## v1.x stability promise

For all `1.x` releases:

1. the tool names present in v1.0 will not be silently repurposed;
2. required arguments will not change incompatibly without a new tool or a major version;
3. modern `2026-07-28` stateless requests remain supported;
4. legacy `2025-06-18` initialize compatibility remains supported throughout `1.x` unless a critical upstream security requirement makes that impossible;
5. a security tightening may reject behavior that was previously unsafe, even in a minor/patch release;
6. repository content will never become an authorization source.

Any planned removal of the legacy protocol belongs to a major release and must be documented before release.

## Conformance regression

`tests/test_v1_stable.py` asserts:

- discovery works without initialize;
- current revision/cache/identity fields are advertised;
- legacy initialize still works;
- modern tool schemas use JSON Schema 2020-12;
- modern responses carry the server identity stamp.

The Python 3.11–3.14 CI matrix executes these checks on every push and pull request.
