# GPTHands v0.4 — ChatGPT Integration UX

v0.4 turns the v0.3 security core into a practical local integration surface without moving authority into the repository.

## Security model

- A workspace must be explicitly trusted before `gpthands serve` starts by default.
- Trust state, approval keys, audit logs, credential references and installer metadata live outside the workspace.
- The local control UI binds only to `127.0.0.1` and uses a per-process CSRF token for mutations.
- Secrets are stored only in an OS credential store. GPTHands has no plaintext credential fallback.
- Secure MCP Tunnel profiles reference `env:CONTROL_PLANE_API_KEY`; literal API keys are not written into tunnel profiles.
- Approval tokens are short-lived, one-time and may be bound to an exact action hash.
- Missing approval tokens trigger a best-effort local desktop notification without exposing command content or secrets.

## First-use flow

```bash
gpthands trust --workspace /path/to/repo
gpthands init-policy --workspace /path/to/repo
gpthands doctor --workspace /path/to/repo
gpthands ui --workspace /path/to/repo
```

The UI opens on a random loopback port by default. Use `--no-browser` to print the URL only.

## OS credential store

Check the active backend:

```bash
gpthands credential-backend
```

Store a Secure MCP Tunnel runtime key without echoing it:

```bash
gpthands credential-set openai-tunnel-runtime
```

Or pipe it explicitly:

```bash
printf '%s' "$CONTROL_PLANE_API_KEY" | gpthands credential-set openai-tunnel-runtime --stdin
```

Backends:

- macOS: Keychain (`security`)
- Windows: Credential Manager (`CredWriteW` / `CredReadW`)
- Linux: Secret Service through `secret-tool`

If no supported backend is available, credential storage fails closed.

## Secure MCP Tunnel

GPTHands does not reimplement the OpenAI tunnel protocol. It delegates transport to the official `tunnel-client` binary.

Preview the exact command plan:

```bash
gpthands tunnel-plan \
  --workspace /path/to/repo \
  --tunnel-id tunnel_0123456789abcdef0123456789abcdef
```

Create the profile:

```bash
gpthands tunnel-init \
  --workspace /path/to/repo \
  --tunnel-id tunnel_0123456789abcdef0123456789abcdef \
  --credential-name openai-tunnel-runtime
```

Run diagnostics:

```bash
gpthands tunnel-doctor \
  --workspace /path/to/repo \
  --tunnel-id tunnel_0123456789abcdef0123456789abcdef \
  --credential-name openai-tunnel-runtime
```

Start the long-lived runtime:

```bash
gpthands tunnel-run \
  --workspace /path/to/repo \
  --tunnel-id tunnel_0123456789abcdef0123456789abcdef \
  --credential-name openai-tunnel-runtime
```

The generated profile uses a local stdio MCP command and health listener `127.0.0.1:0`.

## Workspace trust

```bash
gpthands trust --workspace /path/to/repo
gpthands trust-list
gpthands untrust --workspace /path/to/repo
```

The identity is the SHA-256 of the canonical workspace path. Repository files cannot self-authorize trust.

## Approval UX

The local UI can issue one-time approval tokens bound to a 64-character action SHA-256. The server also emits a local notification when an action reaches a configured approval threshold without a token.

The notification contains only:

- workspace basename;
- risk class;
- a short action-hash prefix.

It does not include command arguments, file content or credentials.

## Diagnostics

```bash
gpthands doctor --workspace /path/to/repo
```

The report covers:

- Python/platform;
- explicit workspace trust;
- policy state;
- OS sandbox availability;
- audit-chain validity;
- credential-store backend;
- official `tunnel-client` availability.

## Local launcher install and rollback

```bash
gpthands install-user
gpthands uninstall-user
```

The installer writes user-level `gpthands-ui` and `gpthands-doctor` launchers. Existing launchers are backed up first. Uninstall restores those backups from the external install manifest.

The installer refuses to replace symlink launchers.
