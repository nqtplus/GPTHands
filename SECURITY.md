# GPTHands Security

GPTHands is designed around one rule: **the model does not own authority**. Local owner-controlled trust state, policy, expiring leases, approval tokens, quotas, audit verification and the OS sandbox own authority.

## Default posture

A fresh workspace has:

- filesystem read enabled only inside the selected workspace;
- filesystem write disabled;
- generic process execution disabled;
- network-capable process execution disabled;
- no allowed generic executables;
- secret-like file paths denied;
- common token values redacted from tool output;
- audit logging outside the workspace by default;
- OS sandboxing required for generic process execution;
- `gpthands serve` refusal until the canonical workspace is explicitly trusted.

## Trust boundaries

Treat prompts, repository source, README/AGENTS instructions, test/build output, dependencies, MCP arguments, generated commands and other tool output as untrusted input. None of them can grant a capability or mark a workspace trusted.

v0.4 workspace trust is stored outside the repository. The identity is derived from the SHA-256 of the canonical resolved workspace path. The local UI can switch only to an already trusted canonical workspace.

## External policy authority and schema v3

The authoritative policy lives outside the repository under the user-controlled GPTHands configuration area. On POSIX, GPTHands requires owner-controlled policy state and refuses unsafe permissions or policy symlinks.

Policy schema v3:

- has an explicit `schema_version`;
- migrates supported historical formats;
- rejects unsupported future versions;
- rejects unknown fields instead of silently accepting security-sensitive typos;
- bounds every numeric quota and lease duration.

Use `gpthands migrate-policy --workspace /path/to/project` to rewrite a supported older policy to the current schema.

## Capability leases

Mutable capabilities remain lease-bound:

- write;
- generic process;
- network.

A boolean permission alone is insufficient. Lease status is evaluated on every action, and GPTHands refuses leases longer than 24 hours.

## Risk and approvals

Mutable/process actions are classified:

```text
READ < WRITE < EXEC < NETWORK < DESTRUCTIVE
```

Generic interpreters/shells such as Python, Node, Bash, Ruby, Perl, PHP and PowerShell are `DESTRUCTIVE` because arbitrary code cannot be safely inferred from argv alone.

Approval tokens are:

- HMAC-SHA-256 signed with a local 256-bit key;
- short-lived (maximum 1 hour);
- workspace and risk bound;
- optionally exact-action bound;
- single-use;
- replay-protected across restarts;
- atomically consumed under an owner-only cross-process file lock.

v0.4 adds an external pending-approval UX queue. The queue is metadata only: workspace identity/path, risk, exact action hash and timestamps. It deliberately does not persist command arguments, file contents, prompts, tool output, credentials or approval tokens.

A missing required token still causes authoritative refusal. Creating a pending queue entry or showing a desktop notification never grants authority.

## OS credential storage

GPTHands has no plaintext fallback for credentials managed through its v0.4 credential interface.

Supported backends are:

- macOS Keychain;
- Windows Credential Manager;
- Linux Secret Service through `secret-tool`.

If the platform backend is unavailable, the credential operation fails.

Secure MCP Tunnel configuration references `env:CONTROL_PLANE_API_KEY`; GPTHands injects the runtime value from the OS credential store into the `tunnel-client` child environment rather than writing a literal key into the generated profile.

## Local control UI

The v0.4 local UI is intentionally not a remotely exposed control plane:

- hard-bound to IPv4 loopback `127.0.0.1`;
- OS-selected random port by default;
- per-process CSRF token required for mutations;
- `Cache-Control: no-store`;
- `X-Frame-Options: DENY`;
- `Referrer-Policy: no-referrer`;
- restrictive CSP with no remote script/resource loading;
- credentials are never rendered.

Pending-action approval is revalidated against the queue for the currently selected workspace before an action-bound token is issued.

## Filesystem and safe editing

GPTHands rejects absolute tool paths, canonicalizes requested paths, checks containment below the selected workspace and blocks common credential paths. Deterministic fuzzing and Hypothesis property tests assert that accepted tool paths remain within the workspace.

Prefer:

```text
preview_edit
  -> diff + base_sha256 + one-time preview_id
apply_edit
  -> validates unchanged base + consumes preview_id
```

Blind overwrite of an existing file remains `DESTRUCTIVE`.

## Process controls

Generic process execution is off by default. When explicitly leased and allowlisted:

- GPTHands invokes argv with `shell=False`;
- stdin is closed;
- a minimal child environment is used instead of inheriting host API keys/tokens;
- timeout/output caps apply;
- action risk and required approval are checked before execution;
- OS sandboxing is required by default.

### Linux

GPTHands uses bubblewrap namespaces when available. The workspace is read-only without a live write lease; HOME and `/tmp` are isolated; system paths are mounted read-only; network is unshared unless an authorized network action requires host networking.

CI verifies both secure fail-closed behavior and real bubblewrap RO/RW + network-namespace enforcement.

### macOS

GPTHands uses a conservative `sandbox-exec`/Seatbelt profile when present, with real macOS integration tests for workspace read/write isolation. Because Apple deprecated the public interface, this remains a compatibility backend. The successor strategy is documented in `docs/PLATFORM_HARDENING.md` and preserves fail-closed migration semantics.

### Windows

GPTHands v0.4 implements a native AppContainer sandbox over a private staged workspace.

Current controls include:

- no AppContainer ACL grant to the user's real repository tree;
- generated AppContainer identity/profile;
- staged workspace ACL set to RO or RW from the live write capability;
- private writable scratch/TEMP area;
- explicit inherited-handle allowlist;
- sanitized child environment;
- network capability omitted by default;
- modern SandboxEngine path when available;
- classic `CreateAppContainerProfile` + `SECURITY_CAPABILITIES` fallback for supported Windows hosts where SandboxEngine is unavailable.

Windows CI launches real AppContainer children and verifies output capture, workspace read, outside-workspace read denial, RO write refusal, RW write success/synchronization, outbound network denial and arbitrary host-environment non-inheritance.

Remaining Windows hardening before v1.0 includes dedicated Job Object descendant containment/resource enforcement, adversarial reparse-point/junction tests, process-tree timeout verification and external review. These are documented as residual work rather than claimed complete.

## Rate and concurrency controls

Policy schema v3 adds bounded operational quotas:

- `max_requests_per_minute`;
- `max_concurrent_actions`;
- `max_queue_seconds`.

`tools/call` is protected by a thread-safe sliding-window rate limiter and bounded semaphore. Quota rejection does not grant additional authority.

## Tamper-evident audit chain

The audit log is stored outside the workspace. v0.3+ audit records contain a sequence number, previous-record digest and SHA-256 record digest. Writes are serialized with a cross-process lock. Historical unchained records are accepted only as a prefix and are cryptographically anchored by the first chained record.

Verify explicitly:

```bash
gpthands audit-verify
```

The chain detects record mutation, insertion/reordering and removal that breaks a later link. It is **tamper-evident, not tamper-proof**. Without an external signed checkpoint, deletion/truncation of the newest tail can remove final chain state without leaving a later contradictory link.

Write content is never copied verbatim into audit records; byte count and SHA-256 fingerprints are used, and known token formats are redacted before durable records are hashed.

## Supply-chain hardening

The runtime package has no third-party Python dependency. CI/release tooling is pinned. CI performs:

- Python 3.11–3.14 security tests;
- deterministic adversarial fuzzing;
- Hypothesis property-based security tests;
- pinned dependency vulnerability auditing;
- two independent wheel builds requiring byte-identical SHA-256 output;
- deterministic CycloneDX 1.6 SBOM generation;
- `SHA256SUMS` generation;
- Linux/macOS/Windows real sandbox integration tests;
- pinned GitHub Actions by immutable commit SHA.

The release workflow supports GitHub/Sigstore build-provenance and SBOM attestations. Tagged releases additionally require the tag to exactly match the package version before release creation.

## Residual risks in v0.4

- Secret detection/redaction remains heuristic.
- macOS still relies on deprecated Seatbelt tooling until a successor backend is implemented and tested.
- Windows still needs Job Object descendant/resource hardening and adversarial reparse-point/process-tree tests before the stable v1.0 boundary claim.
- A user can deliberately weaken process security with `require_os_sandbox=false`; sensitive hosts should not do so.
- Audit hash chaining does not independently prove that the newest tail was not truncated; an externally anchored checkpoint would strengthen this.
- Secure MCP Tunnel transport is delegated to the official tunnel client and remains a separate process/security boundary.
- The risk classifier cannot understand the full semantics of arbitrary programs; OS isolation remains the primary enforcement boundary.
- CI is evidence of implemented checks, not a substitute for an external security assessment.

## Reporting a vulnerability

Use a GitHub private security advisory/vulnerability report when repository settings support it. Do not publish working exploit details for an unpatched vulnerability in a public issue.
