# GPTHands Security

GPTHands is designed around one rule: **the model does not own authority**. Local owner-controlled policy, expiring leases, approval tokens, and the OS sandbox own authority.

## Default posture

A fresh workspace with no external policy has:

- filesystem read enabled only inside the selected workspace;
- filesystem write disabled;
- generic process execution disabled;
- network-capable process execution disabled;
- no allowed generic executables;
- secret-like file paths denied;
- common secret values redacted from tool output;
- audit logging outside the workspace by default.

## Trust boundaries

Treat all of the following as untrusted input:

- prompts;
- repository source code;
- README/AGENTS/instruction files;
- build/test output;
- dependency metadata;
- MCP tool arguments;
- generated commands;
- tool output returned by other systems.

None of these can grant a capability.

### Policy authority is outside the repository

v0.2 no longer trusts `.gpthands.json` in a workspace. The authoritative policy is stored outside the repository, by default under:

```text
~/.config/gpthands/policies/<workspace-id>.json
```

On POSIX, GPTHands requires the policy file to be owner-controlled (`0600`) and refuses a group/world-writable policy directory. Final-component policy symlinks are refused. The policy path itself must resolve outside the selected workspace.

Use `gpthands init-policy` to create policy safely rather than manually copying a file into a repository.

## Capability leases

Mutable capabilities are lease-bound:

- write lease;
- generic process lease;
- network lease.

A boolean such as `allow_write=true` is not enough. The corresponding lease must still be live. Lease status is re-evaluated on every action, so a server that stays running does **not** retain authority after expiry.

GPTHands refuses policy leases granting more than 24 hours of authority. The CLI defaults to short leases (15 minutes).

## Risk levels

Every mutable/process action is classified into one of:

```text
READ < WRITE < EXEC < NETWORK < DESTRUCTIVE
```

Generic shells/interpreters such as Python, Node, Bash, Ruby, Perl, PHP, and PowerShell are classified `DESTRUCTIVE` because an argv allowlist cannot safely infer what arbitrary code will do.

The external policy selects `approval_required_from`. The CLI default is `EXEC`, meaning generic process execution and all higher-risk actions require human approval.

## Human approval tokens

Approval tokens are:

- HMAC-signed with a local 256-bit key;
- short-lived (maximum 1 hour);
- bound to a workspace;
- bound to a minimum risk level;
- optionally bound to an exact action hash;
- single-use;
- replay-protected across server restarts using a local owner-only replay store.

Approval key and replay state live outside the workspace. A token should be treated like a short-lived capability: do not log or publish it.

## Filesystem controls

GPTHands rejects absolute tool paths and canonicalizes requested paths before access. The canonical path must remain below the configured workspace root. This blocks traversal (`../`) and symlink escapes in GPTHands filesystem tools.

Secret-like paths such as `.env`, private keys, `.ssh`, `.aws`, GCloud credentials, and GitHub credential files are denied. Secret redaction is defense in depth; it is not a complete secret-classification system.

### Safe edit path

Prefer `preview_edit` then `apply_edit`:

1. `preview_edit` returns a unified diff, base SHA-256, and one-time preview id;
2. `apply_edit` verifies that the source file still matches the previewed SHA;
3. the preview id is consumed on success;
4. the write remains subject to the live write lease and approval threshold.

`write_file` remains available, but overwriting an existing file is classified `DESTRUCTIVE`.

## Process controls

Generic process execution is **off by default**. If leased and allowlisted:

- executable basename must be in `allowed_commands`;
- `shell=False` is always used by GPTHands;
- stdin is closed;
- host API-key/token environment variables are not inherited;
- runtime and captured output are bounded;
- action risk is classified before execution;
- required human approval is verified before execution;
- an OS sandbox is required by default.

### Linux

When `bubblewrap` is available and `require_os_sandbox=true`, GPTHands uses namespaces and constrained mounts:

- isolated namespace set;
- workspace read-only unless a live write lease exists;
- isolated HOME and `/tmp`;
- minimal read-only system mounts;
- network namespace isolated by default;
- host network shared only for a `NETWORK` action with a live network lease and any required approval.

CI includes real bubblewrap isolation tests for workspace write denial and network namespace isolation.

### macOS

When `sandbox-exec` is present, GPTHands generates a conservative profile for workspace/system reads, bounded writes, and network deny-by-default. Apple has deprecated `sandbox-exec`, so availability varies. If no supported backend exists and OS sandboxing is required, GPTHands refuses the process action instead of silently falling back.

Setting `require_os_sandbox=false` intentionally reduces the security boundary to policy-level controls and should not be used on sensitive hosts.

## Curated Git operations

`git_status` and `git_diff` are dedicated read-only tools. They run with workspace write disabled and network disabled in the OS sandbox and do not require the generic process lease. Prefer them over `run_command(["git", ...])` for read-only repository inspection.

## Child environment

Generic/curated processes receive only a minimal environment such as `PATH`, locale, and `NO_COLOR`, plus an isolated HOME/TMP context. Arbitrary host environment variables are not forwarded.

## Audit log

Default path:

```text
~/.local/state/gpthands/audit.jsonl
```

The audit file must be outside the MCP workspace, must not be a symlink, and is held open with owner-only permissions on POSIX. Write content is not copied verbatim into audit records; byte count and SHA-256 are recorded instead. Known token formats are redacted.

Tamper-evident hash chaining is planned for v0.3.

## Residual risks in v0.2

- Secret-path and value detection is heuristic and cannot identify every credential format.
- macOS isolation relies on a deprecated Apple facility when it is available; a successor backend is still needed for long-term support.
- An intentionally configured `require_os_sandbox=false` policy weakens process isolation.
- Approval replay persistence is local-state based; multi-process/concurrent approval consumption receives stronger locking in future hardening.
- Transport authentication/tunnel security is outside the stdio server and must be provided by the MCP deployment layer.
- Windows OS-level isolation is not implemented yet.

## Reporting a vulnerability

Please use a GitHub private security advisory/vulnerability report when repository settings support it. Do not publish working exploit details for an unpatched vulnerability in a public issue.
