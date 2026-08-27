# GPTHands

**Secure-by-default local coding hands for ChatGPT and MCP clients.**

[![CI](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml/badge.svg)](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml)

GPTHands is a local MCP tool server that lets an AI assistant inspect and work with a selected repository while keeping authority outside the model and outside the repository.

> The model proposes actions. GPTHands policy, leases, approvals, and the OS sandbox decide what is allowed.

## v0.2 security defaults

- Read-only by default
- Canonical workspace jail with traversal and symlink-escape checks
- Secret-path denylist plus output token redaction
- Policy authority stored **outside the workspace**
- Policy/replay/key files locked to owner-only permissions on POSIX
- Write/process/network capabilities require **live time-limited leases**
- Leases are re-evaluated at action time and cannot grant more than 24 hours
- Risk levels: `READ`, `WRITE`, `EXEC`, `NETWORK`, `DESTRUCTIVE`
- Generic interpreters/shells such as Python, Node, Bash are classified `DESTRUCTIVE`
- Human approval tokens are HMAC-signed, short-lived, workspace/risk bound, and replay-protected across restarts
- No `shell=True`; generic commands are argv arrays only
- Executable allowlist remains mandatory
- Linux commands run inside **bubblewrap namespaces** when OS sandboxing is required
- Linux network is denied at the namespace layer unless explicitly granted for a network-classified action
- macOS has a conservative `sandbox-exec` profile when that facility is available; otherwise process execution fails closed when OS sandboxing is required
- Child processes receive a minimal environment instead of host API keys/tokens
- Audit log is outside the workspace, refuses symlinks, and uses mode `0600` on POSIX
- Write content is fingerprinted in audit logs rather than stored verbatim
- Runtime package has no third-party Python dependency

## Architecture

```text
ChatGPT / MCP client
        |
        v
   MCP JSON-RPC
        |
        v
+---------------------+
| GPTHands Server     |
+----------+----------+
           |
           v
+---------------------+
| Risk + Policy       | <--- authority outside repo
| Lease Engine        |
+----------+----------+
           |
      high risk?
       /      \
     yes       no
      |         |
      v         |
 Human approval |
 token          |
      \         /
       v       v
+---------------------+
| OS Sandbox Runner   |
| bwrap / sandbox-exec|
+-----+-----------+---+
      |           |
      v           v
 Guarded FS    Curated Git / Process
      \           /
       v         v
       Workspace
```

## v0.2 tools

Read-only/core:

- `workspace_info`
- `read_file`
- `list_dir`
- `grep`
- `git_status`
- `git_diff`
- `preview_edit`

Mutable:

- `apply_edit` — requires a matching one-time `preview_id` and a live write lease
- `write_file` — live write lease; overwriting an existing file is `DESTRUCTIVE`
- `run_command` — live process lease, executable allowlist, risk classification, approval policy, and OS sandbox

## Install

Requires Python 3.11+.

Linux process isolation requires `bubblewrap`:

```bash
sudo apt-get install bubblewrap    # Debian/Ubuntu
```

Then:

```bash
git clone https://github.com/nqtplus/GPTHands.git
cd GPTHands
python -m pip install -e .
```

## Quick start — read only

A workspace with no external policy is read-only and cannot execute generic processes.

```bash
gpthands --workspace /path/to/project
```

GPTHands speaks newline-delimited MCP JSON-RPC over stdio.

## Grant a short capability lease

Do **not** put authority in the repository. Use the local CLI to create an external policy:

```bash
gpthands init-policy \
  --workspace /path/to/project \
  --lease-seconds 900 \
  --allow-write \
  --allow-process \
  --command git
```

The policy is written under the user's config directory (for example `~/.config/gpthands/policies/<workspace-id>.json`) with owner-only permissions. `.gpthands.example.json` in this repository is only a schema/example; it is not trusted authority.

Inspect the exact policy location with:

```bash
gpthands policy-path --workspace /path/to/project
```

Network capability is separate and must be explicitly leased:

```bash
gpthands init-policy \
  --workspace /path/to/project \
  --lease-seconds 600 \
  --allow-process \
  --allow-network \
  --command git
```

## Human approvals

`init-policy` defaults to `approval_required_from=EXEC`, so generic process execution and higher-risk actions require a human token. Issue a short-lived one-time token locally:

```bash
gpthands approve \
  --workspace /path/to/project \
  --risk EXEC \
  --seconds 300
```

Pass that token as `approval_token` in the relevant MCP tool call. Tokens are signed, expire, are bound to the workspace/risk level, and cannot be replayed after consumption even across GPTHands restarts. For stronger binding, `--action-hash` can bind approval to one exact action.

## Safe editing workflow

Prefer:

```text
preview_edit
   -> unified diff + base_sha256 + one-time preview_id
apply_edit
   -> verifies file did not change + consumes preview_id
```

This avoids blind overwrite workflows and gives the model/user a diff before mutation.

## Linux OS sandbox

With `require_os_sandbox=true` (the default for an external policy), generic commands use bubblewrap with:

- new namespaces;
- workspace mounted read-only unless a live write lease exists;
- isolated `/tmp` and HOME;
- minimal read-only system mounts;
- network namespace isolated by default;
- network sharing only for an explicitly network-classified action with a live network lease and required approval.

CI runs real bubblewrap isolation tests, not only command-construction tests.

## macOS boundary

GPTHands implements a conservative `sandbox-exec` profile when `sandbox-exec` exists. Because Apple has deprecated that facility and availability varies by macOS environment, GPTHands **fails closed** for process tools when `require_os_sandbox=true` and no supported backend exists. Do not disable OS-sandbox requirement on sensitive hosts merely to make a command run.

## Safety model

Repository source, README/AGENTS instructions, build output, dependencies, prompts, and MCP tool arguments are treated as **untrusted data**. They cannot create authority. Mutable authority comes only from the external owner-controlled policy plus unexpired leases and, where required, a human approval token.

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [ROADMAP.md](ROADMAP.md).

## Status

`v0.2` is the OS-sandbox-and-approval milestone. Linux bubblewrap isolation, OS-level network deny-by-default, risk classification, approvals, live leases, external policy storage, curated read-only Git tools, and preview-before-apply editing are implemented. Production hardening such as tamper-evident chained audit records, SBOM, signed releases, fuzzing, and Windows isolation remains for v0.3+.

## License

Apache-2.0. See [LICENSE](LICENSE).
