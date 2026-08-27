# GPTHands

**Secure-by-default local coding hands for ChatGPT and MCP clients.**

GPTHands is a local MCP tool server that lets an AI assistant inspect and work with a selected repository while keeping authority outside the model.

> The model proposes actions. GPTHands policy decides what is allowed.

## Security defaults

- Read-only by default
- Workspace jail with canonical-path and symlink checks
- Secret-file denylist (`.env`, keys, SSH/AWS/GCloud credentials, etc.)
- No `shell=True`; commands are executable + argument arrays
- Command allowlist and dangerous argument detection
- Write and process execution disabled unless explicitly enabled
- Network-capable commands denied by default
- Output secret redaction
- JSONL audit log for every tool call
- No third-party runtime dependency in v0.1

## Architecture

```text
ChatGPT / MCP client
        |
        v
   MCP JSON-RPC
        |
        v
+--------------------+
| GPTHands Server    |
+---------+----------+
          |
          v
+--------------------+
| Policy Engine      |  <- authority boundary
+----+----------+----+
     |          |
     v          v
 Filesystem   Process
  sandbox      sandbox
     |          |
     +-----+----+
           v
      Workspace jail
```

## v0.1 tools

- `workspace_info`
- `read_file`
- `list_dir`
- `grep`
- `write_file` (off by default)
- `run_command` (off by default)

## Quick start

Requires Python 3.11+.

```bash
git clone https://github.com/nqtplus/GPTHands.git
cd GPTHands
python -m pip install -e .
cd /path/to/project
gpthands --workspace .
```

GPTHands speaks newline-delimited MCP JSON-RPC over stdio.

To enable controlled write/process capabilities, create `.gpthands.json` from `.gpthands.example.json` in the workspace and explicitly opt in.

## Safety model

GPTHands treats repository content, prompts, README files, and tool outputs as **untrusted data**. None of them can grant capabilities. Permission comes only from local policy.

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Status

`v0.1` is an initial security-first implementation. It is intentionally conservative. OS-level isolation (Seatbelt/bubblewrap/container profiles), approval UI, secure tunnel packaging, and signed releases are planned next.

## License

Apache-2.0 (planned license file before first tagged release).
