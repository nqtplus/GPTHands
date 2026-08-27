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

Windows execution uses a private staged workspace and a real AppContainer process. CI proves process startup/output capture, workspace read isolation, outside-workspace read denial, RO/RW enforcement, network denial without capability, and sanitized environment behavior.

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

## v1.0 — Stable secure local coding bridge — RC1 internally verified

Current candidate: **`1.0.0rc1`**. Internal implementation and CI gates are complete. Stable `1.0.0` remains blocked on an independent external security review and the final tagged signed/attested release.

- [ ] External security review by an independent reviewer
- [x] Stable MCP compatibility contract: current `2026-07-28` + legacy `2025-06-18`
- [x] Cross-platform packaged installer bundles for Linux, macOS and Windows
- [ ] Tagged signed/attested stable `v1.0.0` release
- [x] Hardened process-tree/resource controls on every declared platform
- [x] Documented secure deployment profiles
- [x] Upgrade/rollback strategy for packaged releases
- [x] Windows classic AppContainer stable path uses suspended launch + Job Object containment
- [x] Windows reparse-point/junction escape refusal before execution and before sync-back
- [x] Real Job Object child inheritance / `KILL_ON_JOB_CLOSE` integration proof
- [x] Real installer install → upgrade → rollback smoke tests on Ubuntu, macOS and Windows
- [x] Reproducible RC wheel + deterministic platform bundles + SBOM + SHA256SUMS

### Stable-release gate

`v1.0.0` must not be tagged as stable until all of the following are true:

1. independent security review completed;
2. critical/high findings fixed or explicitly dispositioned;
3. full CI matrix green on the reviewed commit;
4. package version changed from `1.0.0rcN` to `1.0.0`;
5. release tag matches the package version exactly;
6. release artifacts, checksums, provenance and SBOM attestations are published from that tag.

See `docs/EXTERNAL_SECURITY_REVIEW.md`, `docs/MCP_COMPATIBILITY.md`, `docs/SECURE_DEPLOYMENT_PROFILES.md`, and `docs/UPGRADE_ROLLBACK.md`.
