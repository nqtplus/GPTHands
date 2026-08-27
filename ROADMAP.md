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

## v0.3 — Production hardening

- [ ] Tamper-evident chained audit records
- [ ] Atomic/file-locked approval replay consumption for multi-process use
- [ ] SBOM generation
- [ ] Signed release artifacts and checksums
- [ ] Reproducible build/release pipeline
- [ ] Dependency/vulnerability scanning
- [ ] Fuzz MCP parser, path handling, policy/approval engines
- [ ] Property-based path escape tests
- [ ] Durable macOS isolation successor strategy as Apple deprecates `sandbox-exec`
- [ ] Windows security model and OS sandbox
- [ ] Structured policy schema/version migration
- [ ] Rate limits and concurrency quotas

## v0.4 — ChatGPT integration UX

- [ ] Secure MCP Tunnel setup helper
- [ ] Local status/config UI bound to loopback only
- [ ] Keychain/credential-store integration
- [ ] Workspace switcher with explicit trust state
- [ ] Approval notifications and action-specific approval UX
- [ ] Health/status diagnostics
- [ ] Installer/uninstaller with rollback

## v1.0 — Stable secure local coding bridge

- [ ] External security review
- [ ] Stable MCP compatibility contract
- [ ] Cross-platform installers
- [ ] Signed releases
- [ ] Hardened OS sandbox on supported platforms
- [ ] Documented secure deployment profiles
- [ ] Upgrade/rollback strategy
