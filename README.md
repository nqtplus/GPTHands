# GPTHands

**Secure-by-default local coding hands for ChatGPT and MCP clients.**

[![CI](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml/badge.svg)](https://github.com/nqtplus/GPTHands/actions/workflows/ci.yml)

GPTHands is a local MCP tool server that lets an AI assistant inspect and work with a selected repository while keeping authority outside the model.

> The model proposes actions. GPTHands policy decides what is allowed.

## Security defaults

- Read-only by default
- Workspace jail with canonical-path and symlink checks
- Secret-file denylist (`.env`, keys, SSH/AWS/GCloud credentials, etc.)
- Policy authority file protected from MCP reads/writes
- Policy file ownership/permission checks on POSIX
- No `shell=True`; commands are executable + argument arrays
- Command allowlist, network-subcommand gate, and dangerous argument detection
- Write and process execution disabled unless explicitly enabled
- Network-capable commands denied by default at policy level
- Child processes receive a minimal environment instead of host secrets
- Output secret redaction
- Audit log forced outside the workspace, no symlink, mode `0600` on POSIX
- Write content is fingerprinted in audit logs rather than stored verbatim
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
 Guarded FS   Process policy
     |          |
     +-----+----+
           v
      Workspace root
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

To enable controlled write/process capabilities, copy `.gpthands.example.json` to `.gpthands.json` in the target workspace, keep that policy file owner-controlled, and explicitly opt in. `.gpthands.json` is gitignored and GPTHands tools cannot read or modify it.

## Safety model

GPTHands treats repository content, prompts, README files, AGENTS files, build output, and tool output as **untrusted data**. None of them can grant capabilities. Permission comes only from local policy loaded at server startup.

### Important v0.1 boundary

`run_command` is policy-controlled but **not yet an OS-level process sandbox**. Enabling a general-purpose interpreter or untrusted build system may still let that process access host resources available to the local OS user or reach the network indirectly. Keep process execution disabled on sensitive hosts until v0.2 OS isolation is available.

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [ROADMAP.md](ROADMAP.md).

## Status

`v0.1` is a working security-first MCP core with automated security regression tests on Python 3.11–3.14. OS-level isolation (Linux namespaces/bubblewrap, macOS isolation strategy), human approval tokens, secure tunnel packaging, signed releases, and SBOM are next.

## License

Apache-2.0. See [LICENSE](LICENSE).
