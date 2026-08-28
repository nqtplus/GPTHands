# GPTHands

**Secure-by-default local coding hands for ChatGPT and MCP clients.**

[![CI](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml/badge.svg)](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml)

GPTHands is a local MCP coding bridge that lets an AI assistant inspect, edit, test and run code inside a selected workspace while keeping authority outside both the model and the repository.

> The model proposes actions. GPTHands trust state, external policy, expiring leases, approvals, quotas, audit verification and the OS sandbox decide what is allowed.

## Current status — `1.0.0`

GPTHands v1.0 combines the v0.1–v0.4 security/UX work with the stable-bridge hardening validated on the frozen `1.0.0rc3` baseline `6d9524e809fa56419d73dccfd27324c8c1c0e3dc`.

Stable promotion is backed by a user-approved independent multi-scanner gate:

- full Python 3.11–3.14 and Linux/macOS/Windows integration CI;
- GitHub CodeQL `security-extended + security-and-quality`: **0 unwaived High/Critical blockers**;
- Semgrep Community 1.175.0: **0 findings**;
- Gitleaks 8.30.1 over the full Git history: **0 leaks**;
- OpenSSF Scorecard 5.5.0: Dangerous-Workflow **10**, Token-Permissions **10**, Pinned-Dependencies **8**, Vulnerabilities **10**;
- reproducible wheel, deterministic platform bundles, CycloneDX SBOM, `SHA256SUMS`, and GitHub/Sigstore provenance/attestation.

The machine-readable review record is [`docs/reviews/v1.0.0.json`](docs/reviews/v1.0.0.json). Evidence is tracked in [Issue #1](https://github.com/nqtplus/GPTHands/issues/1). Codex Security was not available as a callable integration during this release and is **not** claimed as having run.

## Security architecture

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

- Current MCP: `2026-07-28` stateless discovery/request model with `server/discover`, server identity metadata and JSON Schema 2020-12 tool schemas.
- Legacy MCP: `2025-06-18` `initialize` compatibility for older clients.
- Client metadata is compatibility data, never authorization data.

See [`docs/MCP_COMPATIBILITY.md`](docs/MCP_COMPATIBILITY.md).

## MCP tools

Read/core: `workspace_info`, `read_file`, `list_dir`, `grep`, `git_status`, `git_diff`, `preview_edit`.

Mutable:

- `apply_edit` — matching preview/base hash + live write lease;
- `write_file` — live write lease; destructive overwrite may require approval;
- `run_command` — executable allowlist, process/network leases, risk/approval checks, quotas and OS sandbox.

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/nqtplus/GPTHands.git
cd GPTHands
python -m pip install -e .
```

Linux secure execution additionally requires bubblewrap.

Recommended first use:

```bash
gpthands trust --workspace /path/to/project
gpthands init-policy --workspace /path/to/project
gpthands doctor --workspace /path/to/project
gpthands ui --workspace /path/to/project
gpthands serve --workspace /path/to/project
```

`serve` refuses an untrusted workspace by default. The local UI binds only to a random `127.0.0.1` port.

## Security controls

- explicit workspace trust stored outside repository content;
- external policy with time-limited write/process/network leases;
- READ / WRITE / EXEC / NETWORK / DESTRUCTIVE risk model;
- exact-action, short-lived, single-use approvals with cross-process replay protection;
- bounded MCP input/read/write/output sizes and rate/concurrency quotas;
- stable POSIX atomic writes anchored to opened directory descriptors to resist parent-symlink swap races;
- Linux bubblewrap namespace/mount isolation and fail-closed unsupported-host behavior;
- macOS conservative Seatbelt compatibility sandbox plus process-group cleanup;
- Windows classic AppContainer + private staged workspace + Job Object process-tree containment;
- Windows reparse/junction refusal before staging and before authorized sync-back;
- OS-backed credential storage with no GPTHands plaintext fallback;
- Secure MCP Tunnel helper using the official OpenAI `tunnel-client` with a minimal environment allowlist;
- tamper-evident audit chain and manual/startup verification.

## Packaged install, upgrade and rollback

Release bundles contain the wheel plus a stdlib bootstrap installer. Installation is side-by-side and digest-bound:

```text
verify wheel SHA-256
      |
install new version
      |
smoke-test new
      |
atomic launcher switch
      |
rollback remains available to verified prior version
```

CI performs real install → upgrade → rollback cycles on Ubuntu, macOS and Windows. See [`docs/UPGRADE_ROLLBACK.md`](docs/UPGRADE_ROLLBACK.md).

## Supply chain and stable release gate

The stable workflow verifies the reviewed-baseline ancestry and permits post-review changes only to review evidence, release-status documentation and exact `1.0.0rcN → 1.0.0` version substitutions. Runtime/security changes require a new reviewed baseline.

Release artifacts include:

- reproducible wheel;
- Linux/macOS/Windows installer bundles;
- CycloneDX 1.6 SBOM;
- `SHA256SUMS`;
- GitHub/Sigstore build provenance and SBOM attestations.

The release workflow uses read-only permissions by default and grants OIDC/attestation or `contents: write` only to the jobs that require those capabilities.

## Residual risks

No scanner or sandbox makes local code execution risk-free. Declared residual risks include heuristic secret redaction, tail-truncation limits of a local-only tamper-evident audit chain, and the deprecated public macOS Seatbelt interface. See [`SECURITY.md`](SECURITY.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md).

The multi-scanner gate is the acceptance criterion for v1.0. The separate [`docs/EXTERNAL_SECURITY_REVIEW.md`](docs/EXTERNAL_SECURITY_REVIEW.md) packet remains available for a future human/Codex Security review and does not imply such a review occurred for this release.

## Documentation

- [`SECURITY.md`](SECURITY.md)
- [`THREAT_MODEL.md`](THREAT_MODEL.md)
- [`ROADMAP.md`](ROADMAP.md)
- [`docs/MCP_COMPATIBILITY.md`](docs/MCP_COMPATIBILITY.md)
- [`docs/SECURE_DEPLOYMENT_PROFILES.md`](docs/SECURE_DEPLOYMENT_PROFILES.md)
- [`docs/UPGRADE_ROLLBACK.md`](docs/UPGRADE_ROLLBACK.md)
- [`docs/reviews/v1.0.0.json`](docs/reviews/v1.0.0.json)

## Release state

**`1.0.0` is the stable promotion of the frozen, independently multi-scanner-validated RC3 baseline.** The release workflow verifies the review gate, rebuilds deterministically, attests the artifacts and publishes tag `v1.0.0` plus the GitHub Release.

## License

Apache-2.0. See [LICENSE](LICENSE).
