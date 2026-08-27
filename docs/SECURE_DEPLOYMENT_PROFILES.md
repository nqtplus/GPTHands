# GPTHands v1 Secure Deployment Profiles

These profiles are operator baselines. Repository content cannot select or weaken a profile.

## Profile A — Inspect only

Use for unfamiliar repositories and initial audits.

```bash
gpthands trust --workspace /path/to/repo
gpthands doctor --workspace /path/to/repo
gpthands serve --workspace /path/to/repo
```

No write/process/network lease is created. This is the preferred first contact with untrusted code.

## Profile B — Local build/test, no network

Use after reviewing the repository and only for explicitly allowlisted executables.

```bash
gpthands init-policy \
  --workspace /path/to/repo \
  --lease-seconds 900 \
  --allow-write \
  --allow-process \
  --command git \
  --command pytest
```

Keep network disabled. Generic interpreters/shells remain high risk and may require action-bound approval.

## Profile C — Short networked maintenance

Use only when a task genuinely requires egress, for example a dependency fetch.

```bash
gpthands init-policy \
  --workspace /path/to/repo \
  --lease-seconds 300 \
  --allow-process \
  --allow-network \
  --command git
```

Network is a separate short lease. Prefer a curated command and one-time action-bound approval rather than enabling an interpreter.

## Profile D — ChatGPT / Secure MCP Tunnel

1. Trust the workspace explicitly.
2. Keep the OpenAI tunnel runtime credential in the OS credential store.
3. Generate the tunnel profile through `gpthands tunnel-init`.
4. Run `gpthands tunnel-doctor` before starting the long-lived tunnel.
5. Keep local control UI on its default random `127.0.0.1` port.

The GPTHands profile references `env:CONTROL_PLANE_API_KEY`; the literal key is not written to the tunnel profile.

## Profile E — High-sensitivity workstation

Recommended constraints:

- never use `--allow-untrusted`;
- never use `--no-require-os-sandbox`;
- keep write/process/network leases short;
- keep approval threshold at `EXEC` or stricter;
- do not allow generic interpreters unless the exact action is reviewed;
- verify the audit chain before and after sensitive work;
- use read-only mode for repositories received from unknown sources;
- do not expose the local UI beyond loopback;
- verify release checksums/attestations before upgrade.

## Platform execution boundaries

### Linux

Bubblewrap provides mount/network namespace isolation. Hosts that cannot enforce the required namespace boundary fail closed. Timeout cleanup kills the full process group and bubblewrap also uses `--die-with-parent`.

### macOS

The current compatibility backend uses `sandbox-exec`/Seatbelt with a separate process group. Timeout cleanup kills the entire group. Because the public Seatbelt interface is deprecated, deployments that require a durable long-term boundary should track the successor plan in `PLATFORM_HARDENING.md`.

### Windows

The stable v1 backend uses classic AppContainer + private staging + Job Object containment. The target is created suspended, assigned to the Job Object, verified, and only then resumed. `KILL_ON_JOB_CLOSE` and explicit job termination prevent descendants from surviving the action. Reparse-point trees are refused before staging/sync.

## Deployment rules that are never recommended

Do not treat any of the following as a secure production profile:

- `--allow-untrusted` for autonomous use;
- `--no-require-os-sandbox` on a sensitive host;
- a 24-hour network/process lease as the normal default;
- allowlisting `bash`, `python`, `node`, PowerShell or similar interpreters without human approval;
- storing tunnel/API credentials in repository files;
- exposing the local status UI on `0.0.0.0` or a LAN interface.
