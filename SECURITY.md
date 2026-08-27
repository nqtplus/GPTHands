# GPTHands Security

GPTHands is designed around one rule: **the model does not own authority**. Local policy owns authority.

## Default posture

A fresh workspace has:

- filesystem read enabled only inside the selected workspace;
- filesystem write disabled;
- process execution disabled;
- network-capable command execution disabled;
- no allowed executables;
- secret-like file paths denied;
- common secret values redacted from tool output;
- audit logging enabled outside the workspace by default.

## Trust boundaries

Treat all of the following as untrusted input:

- prompts;
- repository source code;
- README/AGENTS/instruction files;
- build output;
- test output;
- dependency metadata;
- MCP tool arguments.

None of these can grant a capability. Only `.gpthands.json`, loaded locally at server startup, can opt into write or process capability.

## Filesystem controls

GPTHands rejects absolute paths and canonicalizes requested paths before access. The canonical path must remain below the configured workspace root. This is intended to block traversal (`../`) and symlink escapes.

Secret-like paths such as `.env`, private keys, `.ssh`, `.aws`, GCloud credentials, and GitHub credential files are denied.

## Process controls

Process execution is **off by default**. If explicitly enabled:

- the executable basename must be listed in `allowed_commands`;
- `shell=False` is always used;
- stdin is closed;
- HOME and TMPDIR are temporary isolated directories;
- the parent process environment is not inherited except a minimal PATH/locale set;
- runtime and captured output are bounded;
- known destructive arguments are denied.

### Important v0.1 limitation

This policy layer is **not yet an OS-level process sandbox**. An explicitly allowlisted general-purpose interpreter or build tool may still access resources available to the local OS user through absolute paths or initiate network traffic indirectly. Therefore, do not enable arbitrary interpreters or untrusted build commands on sensitive hosts.

OS-level isolation (macOS Seatbelt/sandbox-exec successor strategy, Linux bubblewrap/namespaces, container profiles), network egress enforcement, and interactive approvals are priorities for the next versions.

## Audit log

Default path:

```text
~/.local/state/gpthands/audit.jsonl
```

Write content is never copied verbatim into the audit log; GPTHands records byte count and SHA-256 instead. Known token formats are redacted.

## Reporting a vulnerability

Please open a GitHub security advisory/private vulnerability report when repository settings support it. Do not publish working exploit details for an unpatched vulnerability in a public issue.
