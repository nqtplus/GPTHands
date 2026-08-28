# GPTHands Roadmap

## v0.1 — Security-first MCP core ✅

- [x] MCP stdio JSON-RPC server
- [x] Read-only default policy and canonical workspace jail
- [x] Traversal/symlink escape protection and secret-like path denylist
- [x] Explicit write/process capabilities and executable allowlist
- [x] `shell=False` argv execution and sanitized child environment
- [x] Timeout/output/resource limits
- [x] External JSONL audit log
- [x] Security regression tests and immutable-action CI
- [x] Threat model and security documentation

## v0.2 — OS sandbox and approvals ✅

- [x] Linux bubblewrap/namespaces sandbox with fail-closed fallback
- [x] Real Linux RO/RW mount + network namespace probes in CI
- [x] macOS conservative `sandbox-exec` integration with real CI tests
- [x] Network deny-by-default at OS layer
- [x] READ / WRITE / EXEC / NETWORK / DESTRUCTIVE risk levels
- [x] Human approval tokens and time-limited capability leases
- [x] Policy authority outside workspace with strict permissions
- [x] Curated Git read tools and preview/base-hash/one-time edit flow
- [x] Persistent approval replay protection
- [x] Python 3.11–3.14 regression matrix

## v0.3 — Production hardening ✅

- [x] Tamper-evident SHA-256 audit chain
- [x] Atomic/file-locked cross-process approval replay consumption
- [x] CycloneDX SBOM, SHA-256 checksums and reproducible wheels
- [x] GitHub/Sigstore provenance/SBOM attestations
- [x] Pinned dependency/vulnerability scanning
- [x] Deterministic fuzzing + Hypothesis property tests
- [x] Policy schema v3, migration and unknown-field rejection
- [x] Rate/concurrency/queue quotas
- [x] Windows AppContainer implementation and real isolation tests

## v0.4 — ChatGPT integration UX ✅

- [x] Secure MCP Tunnel helper using the official `tunnel-client`
- [x] Loopback-only status/config UI with CSRF and restrictive headers
- [x] OS credential stores with no plaintext fallback
- [x] External workspace trust store and workspace switcher
- [x] Pending approval queue + one-click exact-action approval UX
- [x] Diagnostics and user-level installer rollback
- [x] Windows staged AppContainer backend
- [x] Linux/macOS/Windows/property/supply-chain CI coverage

## v1.0 — Stable secure local coding bridge ✅

Stable version: **`1.0.0`**.

Frozen reviewed baseline: **`1.0.0rc3`** at `6d9524e809fa56419d73dccfd27324c8c1c0e3dc`.

- [x] Stable MCP compatibility contract: current `2026-07-28` + legacy `2025-06-18`
- [x] Linux/macOS/Windows real sandbox integration coverage
- [x] Windows classic AppContainer suspended launch + Job Object containment
- [x] Windows reparse/junction escape refusal before execution and sync-back
- [x] Full process-tree cleanup / Job Object inheritance proof
- [x] Stable MCP input/read/edit/output bounds
- [x] Exact action-bound approvals and executable normalization hardening
- [x] Local control UI DNS-rebinding protection
- [x] Secure MCP Tunnel output bounds/redaction + minimal environment allowlist
- [x] OS credential size bounds and fail-closed helper timeout
- [x] Static AST security contract against `eval`/`exec`, shell execution and unsafe deserialization
- [x] Stable POSIX dirfd-anchored atomic writes with symlink-swap/no-clobber race tests
- [x] Cross-platform digest-bound packaged installers with install → upgrade → rollback tests
- [x] Reproducible wheel + deterministic platform bundles + SBOM + `SHA256SUMS`
- [x] Least-privilege release workflow permissions
- [x] Reviewed-baseline ancestry and stable-promotion changed-file allowlist
- [x] Exact RC → stable version-only validation for runtime version files
- [x] Independent multi-scanner stable gate approved with Critical open = 0 / High open = 0
- [x] GitHub CodeQL RC3: 0 unwaived High/Critical blockers
- [x] Semgrep Community RC3: 0 findings
- [x] Gitleaks full-history RC3: 0 leaks across 1,658 commits / 7.54 MB
- [x] OpenSSF Scorecard RC3: Dangerous-Workflow 10, Token-Permissions 10, Pinned-Dependencies 8, Vulnerabilities 10
- [x] Full cross-platform CI #204 green on the reviewed RC3 baseline
- [x] Machine-readable stable review record at `docs/reviews/v1.0.0.json`
- [x] Stable release workflow configured to rebuild, attest and publish `v1.0.0`

### Stable-release evidence

The v1.0 acceptance gate uses independent automated security engines rather than claiming a human or Codex Security audit that did not occur:

1. full cross-platform CI;
2. GitHub CodeQL `security-extended + security-and-quality`;
3. Semgrep Community;
4. Gitleaks over full Git history;
5. OpenSSF Scorecard release-relevant controls;
6. prior threat-model/adversarial review and sandbox/race integration tests.

All blocking criteria are satisfied. Evidence is recorded in `docs/reviews/v1.0.0.json` and GitHub Issue #1.

The separate `docs/EXTERNAL_SECURITY_REVIEW.md` packet remains available for future human/Codex Security review; this release does not claim such a review occurred.

### Repository governance

GitHub repository rulesets were not exposed as configured through the connected API. Branch/ruleset protection remains recommended defense-in-depth for future maintainer governance, but it is not part of the runtime security boundary.

## Post-v1.0

Future development should bump the package to the next prerelease before runtime/security changes land on `main`, then repeat the reviewed-baseline and multi-scanner process before the next stable release.
