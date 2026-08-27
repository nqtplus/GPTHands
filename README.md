# GPTHands

**Secure-by-default local coding hands for ChatGPT and MCP clients.**

[![CI](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml/badge.svg)](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml)

GPTHands is a local MCP tool server that lets an AI assistant inspect and work with a selected repository while keeping authority outside both the model and the repository.

> The model proposes actions. GPTHands policy, leases, approvals, quotas, audit verification, and the OS sandbox decide what is allowed.

## v0.3 highlights

v0.3 keeps the v0.2 OS-sandbox/approval model and adds production hardening:

- read-only by default and policy authority outside the workspace;
- schema-versioned policy with explicit migration and unknown-field rejection;
- live write/process/network leases, maximum 24 hours;
- risk levels `READ`, `WRITE`, `EXEC`, `NETWORK`, `DESTRUCTIVE`;
- HMAC human approvals with atomic cross-process replay protection;
- `preview_edit -> apply_edit` safe edit flow;
- Linux bubblewrap isolation with network deny-by-default;
- macOS `sandbox-exec` compatibility backend with real integration tests;
- Windows generic process execution fails closed until the planned AppContainer backend is implemented;
- SHA-256 chained, locked, tamper-evident audit log with startup/manual verification;
- request-rate, concurrency, and queue quotas;
- deterministic fuzz tests plus Hypothesis security properties;
- reproducible wheel builds, CycloneDX SBOM, SHA-256 checksums, vulnerability scan;
- GitHub/Sigstore provenance and SBOM attestation pipeline, exercised successfully before tagged release use;
- no third-party Python **runtime** dependency.

## Architecture

```text
ChatGPT / MCP client
        |
        v
   MCP JSON-RPC
        |
        v
+-----------------------+
| GPTHands v0.3 Server  |
+-----------+-----------+
            |
   +--------+---------+
   | Policy schema v3 |
   | Risk + leases    |
   | Rate/concurrency |
   +--------+---------+
            |
       high risk?
        /     \
      yes      no
       |        |
       v        |
  Human approval
  atomic replay guard
        \      /
         v    v
+-----------------------+
| OS Sandbox Runner     |
| Linux bwrap / macOS   |
| Seatbelt / fail-close |
+-----------+-----------+
            |
            v
         Workspace
            |
            v
  chained external audit
```

## MCP tools

Read-only/core:

- `workspace_info`
- `read_file`
- `list_dir`
- `grep`
- `git_status`
- `git_diff`
- `preview_edit`

Mutable:

- `apply_edit` — matching one-time preview + live write lease;
- `write_file` — live write lease; existing-file overwrite is `DESTRUCTIVE`;
- `run_command` — process lease, executable allowlist, risk/approval checks, quotas, and OS sandbox.

## Install

Requires Python 3.11+.

Linux secure process execution additionally requires bubblewrap, for example:

```bash
sudo apt-get install bubblewrap
```

Install GPTHands:

```bash
git clone https://github.com/nqtplus/GPTHands.git
cd GPTHands
python -m pip install -e .
```

## Quick start — read only

With no external policy, the workspace remains read-only and generic process execution is unavailable:

```bash
gpthands --workspace /path/to/project
```

GPTHands speaks newline-delimited MCP JSON-RPC over stdio.

## Grant a short capability lease

Authority belongs outside the repository:

```bash
gpthands init-policy \
  --workspace /path/to/project \
  --lease-seconds 900 \
  --allow-write \
  --allow-process \
  --command git
```

The policy is stored under the user's configuration directory, normally:

```text
~/.config/gpthands/policies/<workspace-id>.json
```

`.gpthands.example.json` is documentation only and is not trusted authority.

Network is a separate capability:

```bash
gpthands init-policy \
  --workspace /path/to/project \
  --lease-seconds 600 \
  --allow-process \
  --allow-network \
  --command git
```

Policy v3 also supports bounded operational limits:

```bash
gpthands init-policy \
  --workspace /path/to/project \
  --max-requests-per-minute 120 \
  --max-concurrent-actions 4 \
  --max-queue-seconds 2
```

Migrate an older supported policy:

```bash
gpthands migrate-policy --workspace /path/to/project
```

## Human approvals

Generic execution defaults to requiring approval from `EXEC` and above:

```bash
gpthands approve \
  --workspace /path/to/project \
  --risk EXEC \
  --seconds 300
```

Tokens are signed, short-lived, workspace/risk bound, optionally exact-action bound, and single-use. v0.3 atomically consumes replay state under a cross-process lock.

## Audit verification

The default audit log is outside the workspace:

```text
~/.local/state/gpthands/audit.jsonl
```

Verify the SHA-256 chain explicitly:

```bash
gpthands audit-verify --audit-log ~/.local/state/gpthands/audit.jsonl
```

The chain is **tamper-evident, not tamper-proof**. It detects broken internal links, but independently proving that the newest tail was not truncated requires a future external checkpoint/anchor.

## Platform isolation

### Linux

Bubblewrap provides constrained mounts, isolated HOME/TMP, read-only workspace without a write lease, and network namespace isolation by default. CI verifies both secure fail-closed behavior and real RO/RW + network-namespace enforcement.

### macOS

The current compatibility backend uses a conservative `sandbox-exec`/Seatbelt profile and real macOS integration tests. Apple has deprecated the public facility, so GPTHands documents a durable successor path rather than pretending Seatbelt is permanent.

### Windows

v0.3 intentionally has **no claimed Windows generic-process sandbox**. When OS sandboxing is required, process execution fails closed, and Windows CI verifies that behavior. The staged AppContainer + Job Object design and acceptance tests are in [`docs/PLATFORM_HARDENING.md`](docs/PLATFORM_HARDENING.md).

## Supply-chain checks

CI verifies:

```text
Python 3.11–3.14 security suite
+ deterministic fuzzing
+ Hypothesis properties
+ pip-audit
+ reproducible wheel build
+ CycloneDX 1.6 SBOM
+ SHA256SUMS
+ Linux/macOS sandbox integration
+ Windows fail-closed behavior
```

The release workflow additionally creates GitHub/Sigstore build-provenance and SBOM attestations. A tagged release is accepted only when `vX.Y.Z` exactly matches the package version.

## Security model and limitations

Repository content, prompts, generated commands, dependencies, and tool output are untrusted data and cannot create authority. Strong process security depends on a supported OS sandbox; GPTHands fails closed by default rather than silently falling back.

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), [ROADMAP.md](ROADMAP.md), and [Platform Hardening](docs/PLATFORM_HARDENING.md).

## Status

**v0.3 production hardening is implemented and CI-verified for Linux/macOS execution.** Windows remains intentionally fail-closed until the AppContainer staged-workspace backend is implemented and passes real isolation tests. A tagged `v0.3.0` GitHub Release has not been created by this statement alone; the release workflow is prepared and its signing/attestation path has been exercised successfully.

## License

Apache-2.0. See [LICENSE](LICENSE).
