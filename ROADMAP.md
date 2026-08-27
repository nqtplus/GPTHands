# GPTHands Roadmap

## v0.1 — Security-first MCP core

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

## v0.2 — OS sandbox and approvals

- [ ] Linux bubblewrap/namespaces process sandbox
- [ ] macOS sandbox profile / supported OS isolation strategy
- [ ] Network egress deny-by-default at OS layer
- [ ] Per-action risk levels: READ / WRITE / EXEC / NETWORK / DESTRUCTIVE
- [ ] Human approval token for high-risk operations
- [ ] Time-limited capability leases
- [ ] Policy store outside workspace with strict file permissions
- [ ] Git-specific safe operations instead of generic shell where possible
- [ ] Safe patch API with preview/diff before write

## v0.3 — Production hardening

- [ ] Tamper-evident chained audit records
- [ ] SBOM generation
- [ ] Signed release artifacts and checksums
- [ ] Reproducible build/release pipeline
- [ ] Dependency/vulnerability scanning
- [ ] Fuzz MCP parser, path handling, and policy engine
- [ ] Property-based path escape tests
- [ ] Windows security model
- [ ] Structured policy schema/version migration
- [ ] Rate limits and concurrency quotas

## v0.4 — ChatGPT integration UX

- [ ] Secure MCP Tunnel setup helper
- [ ] Local status/config UI bound to loopback only
- [ ] Keychain/credential-store integration
- [ ] Workspace switcher with explicit trust state
- [ ] Approval notifications
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
