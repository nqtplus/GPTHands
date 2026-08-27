# GPTHands Security

GPTHands is designed around one rule: **the model does not own authority**. Local owner-controlled policy, expiring leases, approval tokens, quotas, and the OS sandbox own authority.

## Default posture

A fresh workspace with no external policy has:

- filesystem read enabled only inside the selected workspace;
- filesystem write disabled;
- generic process execution disabled;
- network-capable process execution disabled;
- no allowed generic executables;
- secret-like file paths denied;
- common secret values redacted from tool output;
- audit logging outside the workspace by default;
- OS sandboxing required for generic process execution.

## Trust boundaries

Treat prompts, repository source, README/AGENTS instructions, test/build output, dependencies, MCP arguments, generated commands, and other tool output as untrusted input. None of them can grant a capability.

## External policy authority and schema v3

The authoritative policy lives outside the repository, normally at:

```text
~/.config/gpthands/policies/<workspace-id>.json
```

On POSIX, GPTHands requires owner-controlled policy state and refuses unsafe permissions or policy symlinks. Policy schema v3:

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

Generic interpreters/shells such as Python, Node, Bash, Ruby, Perl, PHP, and PowerShell are `DESTRUCTIVE` because arbitrary code cannot be safely inferred from argv alone.

Approval tokens are:

- HMAC-SHA-256 signed with a local 256-bit key;
- short-lived (maximum 1 hour);
- workspace and risk bound;
- optionally exact-action bound;
- single-use;
- replay-protected across restarts;
- atomically consumed under an owner-only cross-process file lock.

The replay store is re-read while the lock is held, so two GPTHands processes cannot both validate-and-consume the same nonce through separate in-memory caches.

## Filesystem and safe editing

GPTHands rejects absolute tool paths, canonicalizes requested paths, checks containment below the selected workspace, and blocks common credential paths. Deterministic fuzzing and Hypothesis property tests assert that any accepted path remains within the workspace.

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

CI verifies both secure fail-closed behavior on hosted kernels that prohibit unprivileged namespaces and real bubblewrap RO/RW + network-namespace enforcement through a privileged CI probe.

### macOS

GPTHands uses a conservative `sandbox-exec`/Seatbelt profile when present, with real macOS integration tests for workspace read/write isolation. Because Apple has deprecated the public interface, this is a compatibility backend rather than the long-term design. The successor strategy is documented in `docs/PLATFORM_HARDENING.md` and preserves fail-closed migration semantics.

### Windows

GPTHands v0.3 does **not** claim a Windows OS sandbox. With `require_os_sandbox=true`, generic process execution fails closed, and Windows CI verifies that refusal. The planned backend uses an AppContainer over a private staged workspace plus Job Object resource/process-tree controls. It will not be enabled until real isolation tests pass; see `docs/PLATFORM_HARDENING.md`.

## Rate and concurrency controls

Policy schema v3 adds bounded operational quotas:

- `max_requests_per_minute`;
- `max_concurrent_actions`;
- `max_queue_seconds`.

`tools/call` is protected by a thread-safe sliding-window rate limiter and bounded semaphore. Quota rejection returns a dedicated JSON-RPC error and does not grant additional authority.

## Tamper-evident audit chain

Default audit path:

```text
~/.local/state/gpthands/audit.jsonl
```

v0.3 audit records contain a sequence number, previous-record digest, and SHA-256 record digest. Writes are serialized with a cross-process lock. Existing v0.1/v0.2 unchained records are accepted only as a prefix and are cryptographically anchored by the first v0.3 record.

GPTHands verifies the full chain when opening the logger, and operators can verify it explicitly:

```bash
gpthands audit-verify --audit-log ~/.local/state/gpthands/audit.jsonl
```

The chain detects record mutation, insertion/reordering, and removal that breaks a later link. It is **tamper-evident, not tamper-proof**. Without an external signed checkpoint, deletion/truncation of the newest tail can remove the final chain state without leaving a later link to contradict it. External audit anchoring is therefore still a future hardening opportunity.

Write content is never copied verbatim into audit records; byte count and SHA-256 fingerprints are used, and known token formats are redacted before durable records are hashed.

## Supply-chain hardening

The runtime package still has no third-party Python dependency. CI/release tooling is explicitly pinned. CI now performs:

- Python 3.11–3.14 security tests;
- deterministic adversarial fuzzing;
- Hypothesis property-based security tests;
- pinned dependency vulnerability auditing;
- two independent wheel builds with identical `SOURCE_DATE_EPOCH`, requiring byte-identical SHA-256 results;
- deterministic CycloneDX 1.6 SBOM generation;
- `SHA256SUMS` generation;
- pinned GitHub Actions by immutable commit SHA.

The release workflow has also been exercised successfully with GitHub/Sigstore build-provenance and SBOM attestations. Tagged releases additionally require the tag to exactly match the package version before release creation.

## Residual risks in v0.3

- Secret detection/redaction remains heuristic.
- macOS still relies on deprecated Seatbelt tooling until a successor backend is implemented and tested.
- Windows generic process execution remains unsupported under the secure default because AppContainer isolation is not implemented yet.
- A user can deliberately weaken process security with `require_os_sandbox=false`; sensitive hosts should not do so.
- Audit hash chaining does not independently prove that the newest tail was not truncated; an externally anchored checkpoint would strengthen this.
- Transport authentication and Secure MCP Tunnel configuration are outside the stdio server boundary.
- The risk classifier cannot understand the full semantics of arbitrary programs; OS isolation remains the primary enforcement boundary.

## Reporting a vulnerability

Use a GitHub private security advisory/vulnerability report when repository settings support it. Do not publish working exploit details for an unpatched vulnerability in a public issue.
