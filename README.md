# GPTHands

**Secure-by-default local coding hands for ChatGPT and MCP clients.**

[![CI](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml/badge.svg)](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml)

GPTHands is a local MCP coding bridge that lets an AI assistant inspect, edit, test and run code inside a selected workspace while keeping authority outside both the model and the repository.

> The model proposes actions. GPTHands trust state, external policy, expiring leases, approvals, quotas, audit verification and the OS sandbox decide what is allowed.

## Current status — `1.0.0rc2`

The v1 release candidate combines the v0.1–v0.4 security/UX work with the final stable-bridge hardening:

- modern MCP `2026-07-28` stateless discovery/request support;
- legacy MCP `2025-06-18` initialize compatibility for older clients;
- explicit stable `1.x` MCP/tool compatibility contract;
- Linux bubblewrap, macOS Seatbelt compatibility sandbox and Windows AppContainer isolation;
- Windows **classic AppContainer + Job Object** stable execution path: process is created suspended, attached/verified in the Job Object, then resumed;
- process-tree termination on timeout and descendant cleanup rather than only killing the direct child;
- Windows symlink/junction/reparse-point trees refused before staging and before sync-back;
- stable POSIX writes anchored to an opened directory descriptor to resist parent-symlink swap races and preserve atomic no-clobber semantics;
- Secure MCP Tunnel helper using the official OpenAI `tunnel-client`, with an explicit runtime environment allowlist so unrelated shell secrets are not inherited;
- OS-backed credentials with no GPTHands plaintext fallback, bounded credential size and fail-closed helper timeouts;
- explicit workspace trust and loopback-only local control UI;
- one-time action-bound approvals and pending-approval UX;
- tamper-evident audit chain, cross-process replay protection, rate/concurrency limits;
- reproducible wheels, CycloneDX SBOM, `SHA256SUMS`, vulnerability scan and GitHub/Sigstore attestation workflow;
- versioned **offline cross-platform installer bundles** with install → upgrade → rollback smoke tests on Linux, macOS and Windows.

`1.0.0rc2` is intentionally a release candidate. The repository will not call `v1.0.0` independently security-reviewed until an external reviewer has completed the review packet in [`docs/EXTERNAL_SECURITY_REVIEW.md`](docs/EXTERNAL_SECURITY_REVIEW.md).

## Architecture

```text
ChatGPT / MCP client
        |
        | optional private transport
        v
Official Secure MCP Tunnel
        |
        v
+------------------------------+
| GPTHands v1 MCP Server       |
| modern + legacy compatibility|
+---------------+--------------+
                |
      +---------+----------+
      | Workspace trust    |
      | External policy v3 |
      | Risk + leases      |
      | Rate/concurrency   |
      +---------+----------+
                |
           high risk?
            /      \
          yes       no
           |         |
           v         |
 pending approval + one-time
 action-bound token
            \       /
             v     v
+------------------------------+
| OS sandbox / process tree    |
| Linux: bubblewrap            |
| macOS: Seatbelt compat       |
| Windows: AppContainer + Job  |
+---------------+--------------+
                |
                v
      isolated/staged workspace
                |
                v
       tamper-evident audit
```

Repository content is untrusted data. It cannot grant trust, extend a lease, create an approval, change credential authority or disable the sandbox.

## MCP compatibility

### Current — `2026-07-28`

GPTHands supports the stateless modern model including `server/discover`, response server identity metadata and JSON Schema 2020-12 tool schemas. Modern requests do **not** require the old initialize handshake.

### Legacy — `2025-06-18`

Older clients can continue to use `initialize`. Security behavior is identical in both protocol eras; client metadata is compatibility data, never authorization data.

See [`docs/MCP_COMPATIBILITY.md`](docs/MCP_COMPATIBILITY.md).

## MCP tools

Read/core:

- `workspace_info`
- `read_file`
- `list_dir`
- `grep`
- `git_status`
- `git_diff`
- `preview_edit`

Mutable:

- `apply_edit` — matching preview/base hash + live write lease;
- `write_file` — live write lease; destructive overwrite may require approval;
- `run_command` — executable allowlist, process/network leases, risk/approval checks, quotas and OS sandbox.

## Developer install

Requires Python 3.11+.

```bash
git clone https://github.com/nqtplus/GPTHands.git
cd GPTHands
python -m pip install -e .
```

Linux secure execution additionally requires bubblewrap, for example:

```bash
sudo apt-get install bubblewrap
```

## Recommended first-use flow

```bash
gpthands trust --workspace /path/to/project
gpthands init-policy --workspace /path/to/project
gpthands doctor --workspace /path/to/project
gpthands ui --workspace /path/to/project
gpthands serve --workspace /path/to/project
```

`serve` refuses an untrusted workspace by default. The local UI binds only to a random `127.0.0.1` port.

## Capability leases

Example local build/test lease without network:

```bash
gpthands init-policy \
  --workspace /path/to/project \
  --lease-seconds 900 \
  --allow-write \
  --allow-process \
  --command git
```

Network is a separate capability and should generally have a shorter lease:

```bash
gpthands init-policy \
  --workspace /path/to/project \
  --lease-seconds 300 \
  --allow-process \
  --allow-network \
  --command git
```

`.gpthands.example.json` is documentation only and is not authority.

See [`docs/SECURE_DEPLOYMENT_PROFILES.md`](docs/SECURE_DEPLOYMENT_PROFILES.md) for recommended operating modes.

## Approvals

When an action crosses the configured approval threshold, GPTHands keeps it denied until a valid token is supplied. The external pending queue stores only workspace identity, risk, exact action hash and time metadata; it does not store command/file content or credentials.

Manual exact-action approval remains available:

```bash
gpthands approve \
  --workspace /path/to/project \
  --risk EXEC \
  --seconds 300 \
  --action-hash <64-char-sha256>
```

Tokens are HMAC-signed, short-lived, workspace/risk/action bound, single-use and atomically replay-protected across processes.

## OS credential store and Secure MCP Tunnel

Backends:

- macOS: Keychain;
- Windows: Credential Manager;
- Linux: Secret Service through `secret-tool`.

GPTHands does not use a plaintext fallback. Credential values have a portable size bound, and external Secret Service helper calls are timeout-bounded and fail closed.

For ChatGPT/private local MCP access, GPTHands delegates transport to the official OpenAI `tunnel-client`. Generated profiles reference `env:CONTROL_PLANE_API_KEY`; GPTHands does not write the literal runtime key into the profile. The tunnel process receives a minimal allowlisted runtime environment rather than inheriting unrelated API keys/tokens from the user's shell.

```bash
gpthands credential-set openai-tunnel-runtime
gpthands tunnel-plan --workspace /path/to/project --tunnel-id tunnel_0123456789abcdef0123456789abcdef
gpthands tunnel-init --workspace /path/to/project --tunnel-id tunnel_0123456789abcdef0123456789abcdef --credential-name openai-tunnel-runtime
gpthands tunnel-doctor --workspace /path/to/project --tunnel-id tunnel_0123456789abcdef0123456789abcdef --credential-name openai-tunnel-runtime
```

## Platform isolation

### Linux

Bubblewrap provides constrained mounts, isolated HOME/TMP, read-only workspace without a write lease and network namespace isolation by default. Timeout cleanup targets the full process group, and unsupported namespace enforcement fails closed. Stable host-side writes use an opened directory descriptor plus no-follow/no-clobber operations so a parent path swapped to a symlink after validation cannot redirect the final commit outside that directory handle.

### macOS

A conservative `sandbox-exec`/Seatbelt compatibility profile is exercised on real macOS CI. Commands also run in a separate process group so timeout cleanup terminates descendants. Stable host-side writes use the same dirfd-anchored POSIX commit primitive. Because the public Seatbelt facility is deprecated, the durable successor plan remains documented rather than hidden.

### Windows

The v1 stable execution path uses **classic AppContainer + private staged workspace + Job Object**:

1. reject symlinks/junctions/reparse points;
2. copy the workspace into private staging;
3. apply RO/RW AppContainer ACLs according to the live lease;
4. create the AppContainer process **suspended**;
5. attach it to an owner-side Job Object and verify membership;
6. resume execution;
7. close/terminate the Job Object to clean the complete process tree;
8. re-scan staging for reparse points before any authorized sync-back.

Network capability is omitted by default, host environment variables are sanitized, and the real repository is not directly granted AppContainer ACLs. Host-side atomic writes revalidate the canonical parent identity immediately before commit; model-controlled commands operate on private staging rather than racing the host repository path directly.

## Packaged install, upgrade and rollback

Release bundles contain the wheel plus a stdlib bootstrap installer. Installation is side-by-side and offline:

```text
install old -> install new -> smoke-test new -> atomically switch launcher
                                      |
                                      +-> failure: keep old launcher
```

A rollback smoke-tests the previous installed version before switching the launcher back.

CI performs a real `install old → install current → rollback → install current` sequence on Ubuntu, macOS and Windows.

See [`docs/UPGRADE_ROLLBACK.md`](docs/UPGRADE_ROLLBACK.md).

## Supply-chain and release gates

CI/release tooling verifies or produces:

```text
Python 3.11–3.14 security + MCP compatibility tests
+ deterministic fuzzing
+ static AST runtime security contract
+ Hypothesis properties
+ Linux/macOS/Windows real sandbox tests
+ parent-symlink swap race tests for stable POSIX writes
+ cross-platform installer upgrade/rollback smoke
+ pip-audit
+ reproducible wheel build
+ deterministic platform bundles
+ CycloneDX 1.6 SBOM
+ SHA256SUMS
+ GitHub/Sigstore provenance/attestation workflow
```

The release workflow requires a tag to match the package version and is prepared to attest both wheel and installer ZIP artifacts.

## Audit and residual risks

The audit chain is **tamper-evident, not tamper-proof**. Without an independent external checkpoint, deleting the newest log tail cannot be proven solely from the remaining file.

Other declared residual risks include heuristic secret redaction and the deprecated macOS Seatbelt compatibility interface. CI and an internal threat model are not substitutes for independent review.

See:

- [`SECURITY.md`](SECURITY.md)
- [`THREAT_MODEL.md`](THREAT_MODEL.md)
- [`ROADMAP.md`](ROADMAP.md)
- [`docs/EXTERNAL_SECURITY_REVIEW.md`](docs/EXTERNAL_SECURITY_REVIEW.md)
- [`docs/MCP_COMPATIBILITY.md`](docs/MCP_COMPATIBILITY.md)
- [`docs/SECURE_DEPLOYMENT_PROFILES.md`](docs/SECURE_DEPLOYMENT_PROFILES.md)
- [`docs/UPGRADE_ROLLBACK.md`](docs/UPGRADE_ROLLBACK.md)

## Release state

**`1.0.0rc2` is an internally tested release candidate, not yet an independently reviewed stable `v1.0.0` release.** Stable promotion remains gated by external security review and a verified signed/attested tag release.

## License

Apache-2.0. See [LICENSE](LICENSE).