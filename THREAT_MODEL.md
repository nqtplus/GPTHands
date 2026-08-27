# GPTHands Threat Model

## Security objective

Allow an AI client to perform useful local coding work while minimizing the authority granted to prompts, repository content, dependencies, generated commands, and compromised tools.

GPTHands v0.2 assumes the model can be manipulated. Security decisions therefore live outside model reasoning.

## Primary threats

### T1 — Prompt injection in repository content
An instruction embedded in source, README, test output, or generated text asks the model to access secrets, alter policy, or run destructive commands.

**v0.2 mitigation:** repository content cannot grant capabilities. Policy authority is outside the workspace, mutable authority expires, generic execution is risk-classified, and high-risk operations can require a human approval token.

### T2 — Workspace escape
A tool call attempts `../`, an absolute path, or a symlink to read/write outside the selected repository.

**v0.2 mitigation:** reject absolute tool paths, canonicalize targets, verify workspace containment, test traversal/symlink escape, and mount only the workspace into the Linux process sandbox.

### T3 — Credential disclosure
The agent reads `.env`, SSH/AWS/GCloud credentials, private keys, or hardcoded tokens and returns them to the model.

**v0.2 mitigation:** deny common credential paths, redact common token/key formats, do not inherit arbitrary host environment variables, isolate HOME, and constrain process filesystem visibility through the OS sandbox.

### T4 — Destructive filesystem modification
The model overwrites or destroys source unexpectedly.

**v0.2 mitigation:** write is disabled without a live lease; blind overwrite of an existing file is classified `DESTRUCTIVE`; `preview_edit` + `apply_edit` provides a diff/base hash/one-time preview id; Linux process workspace is read-only without a live write lease.

### T5 — Arbitrary process/shell execution
The model attempts pipes, command substitution, interpreters, or destructive commands.

**v0.2 mitigation:** GPTHands invokes argv directly with `shell=False`; generic executables require allowlisting and a process lease; interpreters/shells are classified `DESTRUCTIVE`; default policy requires approval from `EXEC`; OS sandboxing is required by default.

### T6 — Network exfiltration
A process tries to send workspace data or discovered credentials to an external endpoint.

**v0.2 mitigation:** Linux bubblewrap unshares network by default. Host network is shared only for an action classified `NETWORK` with a live network lease and applicable approval. Common network commands/subcommands are classified before execution. macOS profiles omit network permission unless explicitly granted.

### T7 — Environment-variable theft
A child process prints API keys inherited from the parent.

**v0.2 mitigation:** child processes receive a minimal environment and isolated HOME/TMP; arbitrary host environment variables are not inherited.

### T8 — Resource exhaustion
A command hangs or emits unbounded output.

**v0.2 mitigation:** command timeout, output cap, read/write byte caps, grep result/file caps, and sandbox process separation.

### T9 — Policy escalation
Repository code modifies the authority file, or a symlink tricks GPTHands into loading policy from an attacker-controlled location.

**v0.2 mitigation:** authoritative policy lives outside the workspace, final policy symlinks are refused before canonicalization, POSIX ownership/permission checks are enforced, parent directory must not be group/world writable, and policy leases cannot exceed 24 hours.

### T10 — Stale authority
A server is started during a valid lease and remains privileged after the lease expires.

**v0.2 mitigation:** write/process/network authority is calculated at action time, not cached at startup.

### T11 — Approval replay/forgery
A model reuses a human approval token or alters its risk/workspace/action.

**v0.2 mitigation:** HMAC signature, expiry, workspace binding, minimum-risk binding, optional exact-action binding, random nonce, and persistent consumed-nonce replay store outside the workspace.

### T12 — Audit tampering
An agent modifies evidence of its own actions.

**v0.2 mitigation:** audit log lives outside the workspace, refuses symlinks, is opened owner-only with no-follow semantics where available, and is not exposed by GPTHands filesystem tools.

### T13 — Supply-chain execution during GPTHands install/runtime
A dependency update compromises the local tool server.

**v0.2 mitigation:** GPTHands runtime has no third-party Python dependency. GitHub Actions dependencies are pinned by immutable commit SHA and CI credentials are not persisted after checkout.

## OS sandbox assumptions

### Linux

The strong process boundary assumes `bubblewrap` is installed and usable. If `require_os_sandbox=true` and the backend is unavailable, execution fails closed. CI installs bubblewrap and runs real isolation tests.

### macOS

The v0.2 strategy uses `sandbox-exec` when available. This facility is deprecated by Apple, so the project does not treat it as a permanent long-term boundary. Missing backend + `require_os_sandbox=true` means process execution is refused.

### Windows

No OS sandbox backend is implemented in v0.2.

## Known residual risks

1. Secret detection/redaction is heuristic and incomplete.
2. macOS needs a durable successor to deprecated `sandbox-exec`.
3. Users can deliberately weaken security with `require_os_sandbox=false`.
4. Multi-process races around replay-state consumption need stronger locking/transaction semantics in v0.3.
5. Audit records are append-only but not yet cryptographically chained/tamper-evident.
6. Transport security is external to the stdio server; MCP tunnel/auth configuration remains deployment responsibility.
7. The risk classifier cannot semantically understand every tool. Strong isolation must not rely on classifier accuracy alone.

## Next hardening layer

v0.3 focuses on tamper-evident audit chaining, SBOM, signed/reproducible releases, dependency/vulnerability scanning, fuzzing/property-based adversarial tests, concurrency/rate limits, and Windows isolation design.
