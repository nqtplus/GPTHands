# GPTHands Roadmap

## v0.1 — Security-first MCP core ✅

- [x] MCP stdio JSON-RPC server
- [x] Read-only default policy
- [x] Canonical workspace jail
- [x] Traversal and symlink escape protection
- [x] Secret-like path denylist
- [x] Common token redaction
- [x] Explicit write capability
- [x] Explicit process capability + executable allowlist
- [x] `shell=False` argv execution
- [x] Sanitized child environment
- [x] Timeout/output/resource limits
- [x] External JSONL audit log
- [x] Security regression tests
- [x] CI with immutable action SHAs
- [x] Threat model and security documentation

## v0.2 — OS sandbox and approvals ✅

- [x] Linux bubblewrap/namespaces process sandbox
- [x] Linux fail-closed behavior when unprivileged namespaces are unavailable
- [x] Real Linux bubblewrap RO/RW mount + network namespace enforcement probe in CI
- [x] macOS conservative `sandbox-exec` profile with `system.sb` runtime baseline
- [x] Real macOS read/write sandbox integration tests in CI
- [x] Fail-closed unsupported-backend behavior
- [x] Network egress deny-by-default at OS layer
- [x] Per-action risk levels: READ / WRITE / EXEC / NETWORK / DESTRUCTIVE
- [x] Human approval token for high-risk operations
- [x] Time-limited capability leases re-evaluated at action time
- [x] Policy store outside workspace with strict file permissions
- [x] Git-specific safe read operations instead of generic shell where possible
- [x] Safe edit API with preview/diff + base hash + one-time preview id before write
- [x] Persistent approval replay protection across server restarts
- [x] Python 3.11–3.14 security regression matrix

## v0.3 — Production hardening ✅

- [x] Tamper-evident SHA-256 chained audit records + startup/manual verification
- [x] Atomic/file-locked approval replay consumption for multi-process use
- [x] Deterministic CycloneDX SBOM generation
- [x] SHA-256 release checksums
- [x] GitHub/Sigstore build provenance and SBOM attestations; pipeline exercised successfully
- [x] Reproducible wheel build verified by byte-identical SHA-256 output
- [x] Dependency/vulnerability scanning with pinned `pip-audit` CI tooling
- [x] Deterministic fuzzing of MCP shapes, paths, approval tokens, and versioned policy parsing
- [x] Hypothesis property-based path-escape and token-mutation tests
- [x] Durable macOS successor strategy and fail-closed migration contract documented
- [x] Windows fail-closed security posture and staged AppContainer design documented
- [x] Windows AppContainer OS sandbox implementation and real isolation tests
- [x] Structured policy schema v3 + legacy migration + unknown-field rejection
- [x] Per-server rate limits and concurrency/queue quotas
- [x] Version-consistency regression between package metadata and effective server

Windows execution now uses a private staged workspace and a real AppContainer process. CI proves process startup/output capture, workspace read isolation, outside-workspace read denial, RO/RW enforcement, network denial without capability, and sanitized environment behavior. Windows 11 SandboxEngine is preferred when available; classic AppContainer is the native fallback on supported Windows Server/desktop hosts.

## v0.4 — ChatGPT integration UX ✅

- [x] Secure MCP Tunnel setup helper using the official `tunnel-client`
- [x] Local status/config UI hard-bound to `127.0.0.1`
- [x] Per-process CSRF protection and restrictive local UI response headers
- [x] OS credential-store integration with no plaintext fallback
- [x] Explicit workspace trust store outside repository content
- [x] Trusted-workspace switcher in the local UI
- [x] Approval notifications without command/content leakage
- [x] External pending-approval queue containing only risk + exact action hash metadata
- [x] One-click action-bound, one-time approval UX
- [x] Health/status diagnostics
- [x] User-level installer/uninstaller with backup + rollback
- [x] Windows AppContainer staged-workspace backend
- [x] Package/server version `0.4.0` and CI supply-chain metadata synchronized
- [x] Python 3.11–3.14, Linux, macOS, Windows, property and supply-chain CI regression coverage

See `docs/V04_CHATGPT_INTEGRATION.md` for the integration flow and security model.

## v1.0 — Stable secure local coding bridge

- [ ] External security review
- [ ] Stable MCP compatibility contract
- [ ] Cross-platform packaged installers
- [ ] Tagged signed/attested releases
- [ ] Hardened process-tree/resource controls on every declared platform
- [ ] Documented secure deployment profiles
- [ ] Upgrade/rollback strategy for packaged releases
