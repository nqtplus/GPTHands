# GPTHands Threat Model

## Security objective

Allow an AI client to perform useful local coding work while minimizing the authority granted to prompts, repository content, dependencies, and generated commands.

## Primary threats

### T1 — Prompt injection in repository content
An instruction embedded in source, README, test output, or generated text asks the model to access secrets, alter policy, or run destructive commands.

**v0.1 mitigation:** policy is enforced outside the model; repository content cannot enable write/process capability or change the executable allowlist unless the local user edits `.gpthands.json`.

### T2 — Workspace escape
A tool call attempts `../`, an absolute path, or a symlink to read/write outside the selected repository.

**v0.1 mitigation:** reject absolute paths, canonicalize paths, verify common workspace root, test symlink escapes.

### T3 — Credential disclosure
The agent reads `.env`, SSH/AWS/GCloud credentials, private keys, or hardcoded tokens and returns them to the model.

**v0.1 mitigation:** deny common credential paths and redact common token/key formats from output. This is defense in depth, not a complete secret scanner.

### T4 — Destructive filesystem modification
The model overwrites source or destroys files unexpectedly.

**v0.1 mitigation:** write capability off by default; overwrite requires a separate explicit boolean; writes are atomic; path restrictions remain enforced.

### T5 — Arbitrary shell execution
The model generates shell syntax, command substitution, pipes, or destructive commands.

**v0.1 mitigation:** no shell invocation; argv arrays only; explicit executable allowlist; known destructive flags denied; process capability off by default.

### T6 — Environment-variable theft
A child process prints API keys inherited from the host environment.

**v0.1 mitigation:** child processes receive a minimal new environment; arbitrary host env values are not inherited.

### T7 — Resource exhaustion
A command hangs or emits unbounded output.

**v0.1 mitigation:** command timeout, output cap, read/write byte caps, grep result/file caps.

### T8 — Audit tampering
An agent modifies evidence of its own actions.

**v0.1 mitigation:** default audit file is stored outside the workspace and is not exposed through GPTHands filesystem tools.

## Known residual risks

1. **No OS-level process jail yet.** An allowlisted interpreter/build system can potentially access host resources available to the user.
2. **Network egress is not fully enforceable at policy level.** A non-network executable can invoke network functionality indirectly.
3. **Secret detection is heuristic.** Unknown credential formats may not be redacted.
4. **Local policy file integrity is user-managed.** Future versions should add permission checks/signing or a separate protected policy store.
5. **Transport security is external to the stdio server.** Secure tunnel integration and authentication hardening belong in the deployment layer.

## Security roadmap

The next hardening layer should add OS sandbox profiles, egress enforcement, per-action approval tokens, capability leases with expiry, policy stored outside the workspace, tamper-evident audit chaining, signed releases/SBOM, fuzzing, and cross-platform adversarial tests.
