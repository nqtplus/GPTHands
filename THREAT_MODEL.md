# GPTHands Threat Model

## Security objective

Allow an AI client to perform useful local coding work while minimizing the authority granted to prompts, repository content, dependencies, generated commands, and compromised tools.

GPTHands v0.3 assumes the model can be manipulated. Security decisions therefore live outside model reasoning.

## Primary threats

### T1 — Prompt injection in repository content
Repository instructions or tool output try to convince the model to access secrets, change policy, or run destructive commands.

**Mitigation:** repository content cannot grant authority. External policy, leases, risk classification, human approval, and the OS sandbox are independent enforcement layers.

### T2 — Workspace escape
A tool attempts traversal, an absolute path, or a symlink escape.

**Mitigation:** absolute tool paths are rejected; targets are canonicalized and checked for workspace containment; secret paths are filtered; deterministic fuzz and Hypothesis path properties run in CI.

### T3 — Credential disclosure
The agent attempts to read credential files or inherit host secrets through environment variables.

**Mitigation:** common credential paths are denied, common token formats redacted, HOME/TMP isolated for child processes, arbitrary host environment variables are not forwarded, and supported OS sandboxes constrain filesystem visibility.

### T4 — Destructive modification
The model overwrites source unexpectedly.

**Mitigation:** live write lease required; overwrite is `DESTRUCTIVE`; `preview_edit`/`apply_edit` provides diff, base hash, and one-time preview id; process workspace is read-only without authorized write capability.

### T5 — Arbitrary code/process execution
A command, interpreter, or build tool executes attacker-controlled code.

**Mitigation:** process capability is off by default, executable allowlist applies, interpreters/shells are `DESTRUCTIVE`, approvals can be required from `EXEC`, argv uses `shell=False`, and OS sandboxing is required by default.

### T6 — Network exfiltration
A process sends workspace data or secrets to an external endpoint.

**Mitigation:** Linux network namespace is denied by default; macOS Seatbelt profile denies network unless granted; NETWORK actions require a live network lease and applicable approval. Unsupported secure backends fail closed.

### T7 — Environment-variable theft
A child prints API keys inherited from the parent.

**Mitigation:** child environment is minimal and does not inherit arbitrary token/key variables.

### T8 — Resource exhaustion or request flooding
A command hangs, emits unbounded output, or a client floods tool calls.

**Mitigation:** process timeout/output caps, bounded filesystem/search operations, policy rate limit, maximum concurrent actions, and queue timeout.

### T9 — Policy escalation or ambiguity
Repository code modifies policy, a symlink redirects it, or a typo silently changes security behavior.

**Mitigation:** policy lives outside workspace, owner/permission/symlink checks apply, schema v3 rejects unknown fields and unsupported versions, numeric limits are bounded, and supported legacy schemas have explicit migration logic.

### T10 — Stale authority
A long-running server keeps permissions after a lease expires.

**Mitigation:** write/process/network leases are evaluated at action time rather than cached at startup.

### T11 — Approval replay/forgery and multi-process races
An attacker modifies a token, replays it after consumption, or races two GPTHands processes against the same nonce.

**Mitigation:** HMAC signature, expiry, workspace/risk/action binding, random nonce, owner-only replay state, and atomic check-and-consume under a cross-process file lock. CI races two processes and requires exactly one successful consumption.

### T12 — Audit tampering
An attacker edits, inserts, reorders, or removes evidence.

**Mitigation:** owner-only audit storage outside workspace, no-follow protections, cross-process append locking, SHA-256 previous-record chaining, full verification on startup, explicit `audit-verify`, and legacy-prefix anchoring.

**Residual:** without an external checkpoint, truncating the newest tail can remove the final chain state without leaving a later contradictory link. Hash chaining is tamper-evident, not an external immutable ledger.

### T13 — Supply-chain compromise
Build tooling, CI actions, or dependencies are compromised or replaced.

**Mitigation:** no third-party runtime Python dependency, pinned CI/release tools, immutable GitHub Action SHAs, `pip-audit`, reproducible wheel comparison, deterministic CycloneDX SBOM/checksums, and GitHub/Sigstore provenance/SBOM attestations. The attestation pipeline has been exercised successfully before tagged release use.

### T14 — Parser/policy edge cases
Malformed JSON-RPC shapes, unusual paths, malformed approvals, or strange policy values trigger unsafe exceptions or default-allow behavior.

**Mitigation:** deterministic adversarial fuzz tests cover MCP shapes, paths, tokens, and policy parsing; Hypothesis property tests generate additional path/token cases; unknown policy fields fail closed.

### T15 — Platform sandbox degradation
An OS removes or changes the sandbox facility.

**Mitigation:** `require_os_sandbox=true` refuses generic process execution when a supported backend is unavailable. Linux and macOS have real integration tests. Windows is explicitly fail-closed until a tested AppContainer backend exists. macOS successor and Windows staged-workspace designs are documented in `docs/PLATFORM_HARDENING.md`.

## Platform assumptions

### Linux

The strong process boundary uses bubblewrap when usable. Hosted kernels that reject unprivileged namespace creation must fail closed; CI additionally uses a privileged probe to prove the real RO/RW mount and network-namespace rules.

### macOS

The current compatibility boundary uses `sandbox-exec`/Seatbelt and is exercised on real macOS CI. Because Apple deprecated this public interface, a successor helper/VM-container strategy is required for durable support.

### Windows

No generic process OS sandbox is claimed in v0.3. Secure-default execution fails closed. The planned AppContainer backend uses a private staged workspace and Job Object constraints and must pass the acceptance tests in `docs/PLATFORM_HARDENING.md` before enablement.

## Known residual risks

1. Secret detection/redaction is heuristic and incomplete.
2. macOS still needs an implemented durable successor to deprecated Seatbelt tooling.
3. Windows AppContainer isolation is a design, not an implemented backend.
4. Users can intentionally weaken the boundary with `require_os_sandbox=false`.
5. Audit tail truncation needs external anchoring for strong detection.
6. Transport/Tunnel authentication is outside the stdio server.
7. Risk classification cannot infer arbitrary program semantics; isolation must not depend on classifier correctness alone.

## Next layer

v0.4 focuses on secure ChatGPT/MCP Tunnel UX, local diagnostics/configuration, keychain integration, approval UX, installers/rollback, workspace trust state, and the Windows AppContainer staged-workspace backend.
