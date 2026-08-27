# GPTHands Threat Model

## Security objective

Allow an AI client to perform useful local coding work while minimizing the authority granted to prompts, repository content, dependencies, generated commands, compromised tools and integration transport.

GPTHands v0.4 assumes the model can be manipulated. Security decisions therefore live outside model reasoning and outside repository content.

## Primary threats

### T1 — Prompt injection in repository content
Repository instructions or tool output try to convince the model to access secrets, change policy, mark the workspace trusted or run destructive commands.

**Mitigation:** repository content cannot grant authority. External trust state, policy, leases, risk classification, human approval and the OS sandbox are independent enforcement layers.

### T2 — Workspace escape
A tool attempts traversal, an absolute path or a symlink escape.

**Mitigation:** absolute tool paths are rejected; targets are canonicalized and checked for workspace containment; secret paths are filtered; deterministic fuzz and Hypothesis path properties run in CI.

**Windows residual:** staged-workspace reparse-point/junction adversarial coverage is still a v1.0 hardening item.

### T3 — Credential disclosure
The agent attempts to read credential files, obtain tunnel credentials or inherit host secrets through environment variables.

**Mitigation:** common credential paths are denied, known token formats are redacted, HOME/TMP are isolated for child processes, arbitrary host environment variables are not forwarded, and supported OS sandboxes constrain filesystem visibility. v0.4 credential operations use an OS credential store with no plaintext fallback.

Tunnel profiles use a secret reference (`env:CONTROL_PLANE_API_KEY`) rather than a literal key. The runtime value is supplied only to the official tunnel-client process environment when requested.

### T4 — Destructive modification
The model overwrites source unexpectedly.

**Mitigation:** live write lease required; overwrite may be `DESTRUCTIVE`; `preview_edit`/`apply_edit` provides diff, base hash and one-time preview id; process workspace is read-only without authorized write capability.

### T5 — Arbitrary code/process execution
A command, interpreter or build tool executes attacker-controlled code.

**Mitigation:** process capability is off by default, executable allowlist applies, interpreters/shells are `DESTRUCTIVE`, approvals can be required from `EXEC`, argv uses `shell=False`, and OS sandboxing is required by default.

### T6 — Network exfiltration
A process sends workspace data or secrets to an external endpoint.

**Mitigation:** Linux network namespace is denied by default; macOS Seatbelt denies network unless granted; Windows AppContainer omits network capability by default. NETWORK actions require a live network lease and applicable approval. Unsupported secure backends fail closed.

### T7 — Environment-variable theft
A child prints API keys inherited from the parent.

**Mitigation:** child environment is minimal and does not inherit arbitrary token/key variables. Windows CI includes an explicit host-environment sentinel non-inheritance test.

### T8 — Resource exhaustion or request flooding
A command hangs, emits unbounded output or a client floods tool calls.

**Mitigation:** process timeout/output caps, bounded filesystem/search operations, policy rate limit, maximum concurrent actions and queue timeout.

**Windows residual:** dedicated Job Object descendant/resource enforcement and full process-tree timeout verification remain stable-release hardening targets.

### T9 — Policy/trust escalation or ambiguity
Repository code modifies policy or trust state, a symlink redirects authority, or a typo silently changes security behavior.

**Mitigation:** policy and trust state live outside workspace, canonical workspace identity is used, owner/permission/symlink checks apply where relevant, schema v3 rejects unknown fields and unsupported versions, numeric limits are bounded, and supported legacy schemas have explicit migration logic.

### T10 — Stale authority
A long-running server keeps permissions after a lease expires.

**Mitigation:** write/process/network leases are evaluated at action time rather than cached at startup.

### T11 — Approval replay/forgery and multi-process races
An attacker modifies a token, replays it after consumption or races two GPTHands processes against the same nonce.

**Mitigation:** HMAC signature, expiry, workspace/risk/action binding, random nonce, owner-only replay state and atomic check-and-consume under a cross-process file lock. CI races two processes and requires exactly one successful consumption.

### T12 — Approval UX confusion or spoofing
A local UI request tricks the user into approving a different action than the one the MCP server requested.

**Mitigation:** missing approvals are recorded as minimal pending metadata keyed by exact action hash and workspace identity. The loopback UI re-reads the queue for the currently selected workspace before issuing an action-bound token. Browser-supplied hashes that are no longer pending are refused. Notifications carry only a short hash prefix and never grant authority.

### T13 — Local control UI exposure
A network peer or malicious webpage attempts to reach the local control surface or submit state-changing requests.

**Mitigation:** the UI binds only to `127.0.0.1`, defaults to an OS-selected random port, requires a per-process CSRF token for mutations, disables framing/referrer/cache leakage and uses a restrictive CSP with no remote resource loading.

**Residual:** loopback is not an authentication boundary against another malicious process running as the same local user. GPTHands therefore keeps sensitive authority action-bound, short-lived and outside repository content rather than treating the browser UI as a privileged network identity.

### T14 — Audit tampering
An attacker edits, inserts, reorders or removes evidence.

**Mitigation:** owner-only audit storage outside workspace, no-follow protections, cross-process append locking, SHA-256 previous-record chaining, full verification on startup, explicit `audit-verify` and historical-prefix anchoring.

**Residual:** without an external checkpoint, truncating the newest tail can remove final chain state without leaving a later contradictory link. Hash chaining is tamper-evident, not an external immutable ledger.

### T15 — Supply-chain compromise
Build tooling, CI actions or dependencies are compromised or replaced.

**Mitigation:** no third-party runtime Python dependency, pinned CI/release tools, immutable GitHub Action SHAs, `pip-audit`, reproducible wheel comparison, deterministic CycloneDX SBOM/checksums and GitHub/Sigstore provenance/SBOM attestation support.

### T16 — Parser/policy edge cases
Malformed JSON-RPC shapes, unusual paths, malformed approvals or strange policy values trigger unsafe exceptions or default-allow behavior.

**Mitigation:** deterministic adversarial fuzz tests cover MCP shapes, paths, tokens and policy parsing; Hypothesis property tests generate additional path/token cases; unknown policy fields fail closed.

### T17 — Platform sandbox degradation
An OS removes or changes the sandbox facility.

**Mitigation:** `require_os_sandbox=true` refuses generic process execution when a supported backend is unavailable. Linux, macOS and Windows have real integration tests. macOS retains a fail-closed successor strategy. Windows supports a modern SandboxEngine path plus classic AppContainer fallback on supported hosts.

### T18 — Tunnel/config secret leakage
Integration setup accidentally writes the runtime key to a profile, command log or repository.

**Mitigation:** GPTHands delegates transport to the official tunnel client, generates an environment-variable secret reference rather than a literal key, offers OS-backed secret storage, never renders stored credentials in the local UI and keeps the health listener on loopback.

## Platform assumptions

### Linux

The strong process boundary uses bubblewrap when usable. Hosted kernels that reject unprivileged namespace creation must fail closed; CI additionally uses a privileged probe to prove real RO/RW mount and network-namespace rules.

### macOS

The current compatibility boundary uses `sandbox-exec`/Seatbelt and is exercised on real macOS CI. Because Apple deprecated this public interface, a successor helper/VM-container strategy is required for durable stable support.

### Windows

v0.4 uses a native AppContainer over a private staged workspace. The real repository is not directly ACL-granted to the AppContainer identity. CI verifies real process startup, workspace read, outside-read denial, RO/RW behavior, network denial and environment isolation.

Windows 11 SandboxEngine is preferred when available; classic `CreateAppContainerProfile` + process security-capabilities attributes provide the supported fallback path.

Remaining hardening includes Job Object descendant/resource enforcement, adversarial reparse-point/junction tests and full process-tree kill/timeout verification.

## Known residual risks

1. Secret detection/redaction is heuristic and incomplete.
2. macOS still needs an implemented durable successor to deprecated Seatbelt tooling.
3. Windows needs stronger descendant-process/resource and reparse-point hardening before the v1.0 stable security claim.
4. Users can intentionally weaken the boundary with `require_os_sandbox=false`.
5. Audit tail truncation needs external anchoring for strong detection.
6. A malicious process already running as the same local OS user may interact with loopback/UI state; action-bound approvals and OS-local authority reduce but do not eliminate that same-user threat.
7. Tunnel transport is a separate official-client boundary; GPTHands does not independently verify OpenAI control-plane implementation internals.
8. Risk classification cannot infer arbitrary program semantics; isolation must not depend on classifier correctness alone.
9. CI is evidence, not an external penetration test or formal verification.

## Next layer

v1.0 focuses on external security review, packaged cross-platform installers, stable MCP compatibility, stronger process-tree/resource controls, durable macOS isolation, documented deployment profiles and signed/attested stable releases.
