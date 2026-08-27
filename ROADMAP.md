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

## v1.0 — Stable secure local coding bridge — RC2 internally verified

Current candidate: **`1.0.0rc2`**. Internal implementation and security gates are complete. Stable `1.0.0` remains blocked on an independent external security review and the final tagged signed/attested release.

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
- [x] Workflow-enforced stable-release review metadata gate
- [x] Reviewed-baseline ancestry + post-review changed-file allowlist verification
- [x] Exact RC → stable version-only validation for `pyproject.toml`, `__init__.py` and `stable_server.py`
- [x] Real temporary-Git-history tests proving post-review runtime injection is rejected
- [x] Mandatory wheel SHA-256 verification before packaged install
- [x] Same-version wheel substitution refusal + per-version local digest binding
- [x] Digest-bound rollback marker verification before launcher switch
- [x] Direct symlink refusal for wheel/install root/bin/releases/version targets and managed installer state
- [x] Stable MCP stdio input size bound and bounded read/edit/output memory behavior
- [x] Exact action-bound approvals; no unbound approval-token fallback
- [x] Executable normalization/path-qualified allowlist bypass protection
- [x] Local control UI DNS-rebinding Host-header rejection
- [x] Secure MCP Tunnel output bounds/redaction and minimal environment allowlist
- [x] OS credential secret-size bound and fail-closed Secret Service helper timeout
- [x] Static AST security contract rejecting runtime `eval`/`exec`, `os.system`/`os.popen`, unsafe deserialization imports and `shell=True`
- [x] Stable POSIX atomic writes anchored to opened directory handles with parent-symlink swap and no-clobber race tests

### Stable-release gate

`v1.0.0` must not be tagged as stable until all of the following are true:

1. independent security review completed against the final RC baseline commit;
2. critical/high findings fixed or explicitly dispositioned, with `critical_open == 0` and `high_open == 0` in the review record;
3. full CI matrix green on the final reviewed/fixed RC baseline;
4. `docs/reviews/v1.0.0.json` records the real independent reviewer, reviewed SHA, timezone-qualified completion time and HTTPS report;
5. stable promotion changes only review evidence, release-status documentation and exact `1.0.0rcN → 1.0.0` version substitutions;
6. release workflow verifies reviewed-commit ancestry and rejects any post-review runtime/security change;
7. release tag matches the package version exactly;
8. release artifacts, SHA256SUMS, provenance and SBOM attestations are published from that tag.

Tracking issue: https://github.com/nqtplus/GPTHands/issues/1

### Repository-governance recommendation

The repository currently exposes no GitHub repository rulesets through the connected API. Before a public stable release, configure a GitHub ruleset/branch policy requiring the full CI workflow for protected release changes if the repository plan/settings support it. This is defense-in-depth around maintainer workflows; it does not replace the runtime security model or the external-review gate.

See `docs/EXTERNAL_SECURITY_REVIEW.md`, `docs/MCP_COMPATIBILITY.md`, `docs/SECURE_DEPLOYMENT_PROFILES.md`, and `docs/UPGRADE_ROLLBACK.md`.
