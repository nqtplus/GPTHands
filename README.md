# GPTHands

**Secure-by-default local coding hands for ChatGPT and MCP clients.**

[![CI](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml/badge.svg)](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml)

GPTHands is a local MCP coding bridge that lets an AI assistant inspect, edit, test and run code inside a selected workspace while keeping authority outside both the model and the repository.

> The model proposes actions. GPTHands trust state, policy, leases, approvals, quotas, audit verification and the OS sandbox decide what is allowed.

## v0.4 highlights

v0.4 adds a practical ChatGPT integration layer on top of the hardened v0.3 core:

- explicit workspace trust outside repository content;
- trusted-workspace switcher;
- local status/config UI hard-bound to `127.0.0.1`;
- per-process CSRF token and restrictive browser security headers;
- OS-backed credential storage with **no plaintext fallback**;
- Secure MCP Tunnel helper that delegates transport to the official OpenAI `tunnel-client`;
- tunnel profiles reference `env:CONTROL_PLANE_API_KEY` instead of writing literal keys;
- local approval notifications that do not expose command arguments, file content or credentials;
- external pending-approval queue containing only risk + exact action hash metadata;
- one-click action-bound, one-time approval UX;
- health/security diagnostics;
- user-level launcher install/uninstall with backup and rollback;
- real Windows AppContainer staged-workspace isolation with CI enforcement tests;
- Python 3.11–3.14 security matrix, Linux/macOS/Windows sandbox tests, property tests and reproducible supply-chain build checks.

The package and effective server version are `0.4.0`.

## Architecture

```text
ChatGPT / MCP client
        |
        | private local connection when needed
        v
Official Secure MCP Tunnel client
        |
        v
+-----------------------------+
| GPTHands v0.4 MCP Server    |
+-------------+---------------+
              |
     +--------+---------+
     | Explicit trust   |
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
 pending approval queue
 + local notification
 + action-bound token
          \      /
           v    v
+-----------------------------+
| OS Sandbox Runner           |
| Linux: bubblewrap           |
| macOS: Seatbelt compat      |
| Windows: AppContainer       |
+-------------+---------------+
              |
              v
     isolated/staged workspace
              |
              v
     tamper-evident audit
```

Repository content is treated as untrusted data. It cannot grant itself trust, extend a lease, issue an approval token or change the external policy authority.

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
- `write_file` — live write lease; existing-file overwrite may be `DESTRUCTIVE`;
- `run_command` — process lease, executable allowlist, risk/approval checks, quotas and OS sandbox.

## Install

Requires Python 3.11+.

```bash
git clone https://github.com/nqtplus/GPTHands.git
cd GPTHands
python -m pip install -e .
```

Linux secure process execution additionally requires bubblewrap, for example:

```bash
sudo apt-get install bubblewrap
```

## Recommended first-use flow

Explicitly trust the canonical workspace first:

```bash
gpthands trust --workspace /path/to/project
```

Create a read-only/default external policy:

```bash
gpthands init-policy --workspace /path/to/project
```

Check the local security/integration state:

```bash
gpthands doctor --workspace /path/to/project
```

Open the local control UI:

```bash
gpthands ui --workspace /path/to/project
```

The UI binds only to a random port on `127.0.0.1` by default. It does not render stored credentials.

Start the MCP stdio server:

```bash
gpthands serve --workspace /path/to/project
```

`serve` refuses an untrusted workspace by default. `--allow-untrusted` exists only as an explicit compatibility override and is not the recommended integration path.

## Workspace trust

```bash
gpthands trust --workspace /path/to/project
gpthands trust-list
gpthands untrust --workspace /path/to/project
```

Workspace identity is derived from the SHA-256 of the canonical resolved path. Trust state is stored outside the repository.

The local UI can switch only to workspaces already present in this trust store.

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

Network is a separate capability:

```bash
gpthands init-policy \
  --workspace /path/to/project \
  --lease-seconds 600 \
  --allow-process \
  --allow-network \
  --command git
```

Operational quotas are bounded independently:

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

`.gpthands.example.json` is documentation only and is never trusted authority.

## Human approvals

Generic execution defaults to requiring approval from `EXEC` and above.

When an action needs approval and no token is supplied, v0.4:

1. records a pending request outside the repository using only workspace identity, risk and exact action hash;
2. emits a best-effort local desktop notification containing only workspace basename, risk and a short hash prefix;
3. shows the exact pending action in the loopback UI;
4. lets the user issue a short-lived, one-time token bound to that exact action.

Manual CLI approval remains available:

```bash
gpthands approve \
  --workspace /path/to/project \
  --risk EXEC \
  --seconds 300 \
  --action-hash <64-char-sha256>
```

Approval tokens are signed, short-lived, workspace/risk bound, optionally exact-action bound and single-use. Replay state is consumed atomically under a cross-process lock.

## OS credential store

Show the selected backend:

```bash
gpthands credential-backend
```

Store a secret without placing it in a GPTHands plaintext file:

```bash
gpthands credential-set openai-tunnel-runtime
```

Backends:

- macOS: Keychain;
- Windows: Credential Manager;
- Linux: Secret Service through `secret-tool`.

If no supported backend exists, GPTHands fails the credential operation instead of falling back to plaintext.

## Secure MCP Tunnel

GPTHands does **not** reimplement OpenAI's tunnel transport. The helper builds and executes commands for the official `tunnel-client` binary.

Preview the exact setup without writing a profile:

```bash
gpthands tunnel-plan \
  --workspace /path/to/project \
  --tunnel-id tunnel_0123456789abcdef0123456789abcdef
```

Create/update the profile using an OS-stored runtime key:

```bash
gpthands tunnel-init \
  --workspace /path/to/project \
  --tunnel-id tunnel_0123456789abcdef0123456789abcdef \
  --credential-name openai-tunnel-runtime
```

Validate it:

```bash
gpthands tunnel-doctor \
  --workspace /path/to/project \
  --tunnel-id tunnel_0123456789abcdef0123456789abcdef \
  --credential-name openai-tunnel-runtime
```

Run the long-lived tunnel client:

```bash
gpthands tunnel-run \
  --workspace /path/to/project \
  --tunnel-id tunnel_0123456789abcdef0123456789abcdef \
  --credential-name openai-tunnel-runtime
```

Generated profiles use `env:CONTROL_PLANE_API_KEY`, a local stdio MCP command and a loopback health listener (`127.0.0.1:0`). Literal runtime keys are not written into the generated profile by GPTHands.

See [`docs/V04_CHATGPT_INTEGRATION.md`](docs/V04_CHATGPT_INTEGRATION.md).

## Health diagnostics

```bash
gpthands doctor --workspace /path/to/project
```

Checks include:

- Python/platform;
- explicit workspace trust;
- policy state;
- OS sandbox backend;
- tamper-evident audit chain;
- OS credential-store backend;
- official `tunnel-client` availability.

## Local UX launcher install and rollback

```bash
gpthands install-user
gpthands uninstall-user
```

The installer creates user-level `gpthands-ui` and `gpthands-doctor` launchers. If a target launcher already exists it is backed up first, and uninstall restores the backup from an external install manifest. Symlink launcher targets are refused.

## Audit verification

The default audit log is outside the workspace. Verify it explicitly with:

```bash
gpthands audit-verify
```

The SHA-256 chain is **tamper-evident, not tamper-proof**. It detects broken internal links; independently proving that the newest tail was not truncated still requires an external checkpoint/anchor.

## Platform isolation

### Linux

Bubblewrap provides constrained mounts, isolated HOME/TMP, read-only workspace without a write lease and network namespace isolation by default. CI exercises both fail-closed behavior and real RO/RW + network isolation.

### macOS

The current compatibility backend uses a conservative `sandbox-exec`/Seatbelt profile and real macOS integration tests. Because the public facility is deprecated, GPTHands retains a documented fail-closed successor strategy rather than treating it as a permanent interface.

### Windows

Windows generic process execution now uses a **real AppContainer boundary** with a private staged workspace.

Current properties include:

- real repository is not directly ACL-granted to the sandbox identity;
- staged workspace receives AppContainer ACLs;
- workspace is read-only when no live write capability exists;
- write-enabled staging synchronizes changes back only after sandbox completion;
- outside-workspace reads are denied;
- network is denied without an explicit AppContainer network capability;
- child environment is sanitized;
- Windows 11 SandboxEngine is preferred when available;
- classic AppContainer is used as the native fallback on supported Windows Server/desktop hosts.

Windows CI launches a real AppContainer child and verifies startup/output, workspace reads, outside-read denial, RO/RW behavior, network denial and environment isolation.

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
+ Linux/macOS/Windows sandbox integration
```

The release workflow additionally creates GitHub/Sigstore build-provenance and SBOM attestations. A tagged release is accepted only when `vX.Y.Z` exactly matches the package version.

## Security model and limitations

Repository content, prompts, generated commands, dependencies and tool output are untrusted data and cannot create authority. Strong process security depends on a supported OS sandbox; GPTHands fails closed by default rather than silently dropping to an unsandboxed process.

v0.4 does not claim that a successful CI suite replaces an external security audit. Packaged cross-platform installers, external security review, stable compatibility contract and tagged stable release remain v1.0 work.

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), [ROADMAP.md](ROADMAP.md), [Platform Hardening](docs/PLATFORM_HARDENING.md), and [v0.4 ChatGPT Integration](docs/V04_CHATGPT_INTEGRATION.md).

## Status

**v0.4 is implemented and CI-verified on the declared test matrix.** This statement does not by itself mean a tagged `v0.4.0` GitHub Release has been created.

## License

Apache-2.0. See [LICENSE](LICENSE).
