# GPTHands Platform Hardening Strategy

This document defines the OS-isolation boundary and the remaining hardening work without weakening GPTHands' fail-closed model.

## Security invariant

A platform backend is considered usable for generic process execution only when it can enforce the required boundary independently of model intent:

1. workspace-scoped filesystem visibility;
2. read-only workspace when no live write lease exists;
3. no arbitrary host credential/home-directory inheritance by default;
4. network deny-by-default;
5. bounded process lifetime;
6. no silent fallback to an unsandboxed process when `require_os_sandbox=true`.

A backend that only limits CPU/memory or only changes process integrity level is not accepted as the primary isolation boundary.

## Linux

The current backend uses bubblewrap with constrained mounts, private HOME/TMP, an RO or RW workspace bind selected from the live write capability, and a separate network namespace when network access is denied.

CI exercises both fail-closed behavior on an unprivileged path and a real privileged bubblewrap isolation probe.

## macOS

### Current compatibility backend

`sandbox-exec`/Seatbelt remains the low-overhead compatibility backend where it is present. CI executes real read/write isolation tests on a GitHub macOS runner.

Apple has deprecated the public `sandbox-exec` interface, so GPTHands does not treat it as a permanent platform contract.

### Durable successor

The preferred long-term boundary is a dedicated sandbox helper with a VM/container isolation option:

```text
GPTHands MCP process
        |
        | explicit workspace grant
        v
sandbox helper
        |
        +--> isolated VM/container filesystem
        |       /workspace  (RO or RW)
        |       /tmp        (private)
        |       no host $HOME
        |
        +--> egress disabled unless lease + approval allow it
```

The host-side GPTHands process remains responsible for policy, leases, approvals, audit and change review.

### Migration rule

The Seatbelt backend stays supported only while its real integration tests pass. If a future macOS image removes or changes it, GPTHands must fail closed until a successor backend passes equivalent tests. There is no automatic downgrade to policy-only execution.

## Windows

### v0.4 implementation

Windows generic process execution now uses a **real AppContainer process operating on a private staged workspace**.

```text
real repository
     |
     | private copy
     v
per-action staging root
     |
     | AppContainer SID ACL
     | workspace = RO or RW
     | private scratch/TEMP = RW
     v
AppContainer process
  - no network capability by default
  - sanitized child environment
  - explicit inherited-handle allowlist
     |
     | successful RW action only
     v
synchronize regular-file changes
     |
     v
real repository
```

The real repository is not ACL-granted to the AppContainer identity. The classic backend stages the workspace first, maps workspace arguments to the staging tree, grants the generated AppContainer SID only the required staging access, executes there, and synchronizes regular-file changes back only for a write-enabled action.

### Process creation backends

GPTHands supports two native AppContainer creation paths:

1. **Windows SandboxEngine path** — preferred when `Experimental_CreateProcessInSandbox` is available from `processmodel.dll`.
2. **Classic AppContainer path** — native fallback using `CreateAppContainerProfile` plus `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` and `CreateProcessW`.

The classic path is required for Windows Server environments where the newer SandboxEngine export is unavailable.

The launcher carries the minimum Windows host environment needed for AppContainer startup, including `LOCALAPPDATA`, while still refusing arbitrary host-environment inheritance. Output/error handles are inherited through an explicit handle allowlist.

### Current enforced properties

The v0.4 Windows CI suite launches real confined processes and verifies:

1. AppContainer process startup and output capture;
2. a marker inside the workspace is readable;
3. a sibling marker outside the workspace is not readable;
4. an RO staged workspace rejects a write;
5. an RW staged workspace accepts a write and the regular-file result is synchronized back;
6. outbound access fails when no AppContainer network capability is granted;
7. an arbitrary host environment sentinel is not inherited by the child;
8. the SandboxSpec profile omits `internetClient` when network access is denied.

A backend setup failure is treated as an isolation failure, not as permission to execute unsandboxed.

### Important remaining Windows hardening

The v0.4 AppContainer backend closes the previous “no Windows sandbox” gap, but the following are still explicit hardening targets before the stable v1.0 claim:

- dedicated Job Object containment for descendant process-tree cleanup and stronger per-tree CPU/memory limits;
- adversarial reparse-point/junction escape tests across staging and synchronization;
- explicit descendant-process inheritance tests proving child processes remain inside the intended AppContainer/process-tree boundary;
- full-process-tree timeout/kill verification;
- stricter transactional change synchronization and conflict handling for complex directory mutations;
- external security review of the Windows ACL/AppContainer boundary.

These items remain roadmap work; they are not silently claimed as completed by the current AppContainer integration tests.

## Cross-platform fail-closed rule

When `require_os_sandbox=true`, failure to construct or launch the declared OS isolation backend must stop the target command. GPTHands must not automatically retry the same target directly on the host.

The platform-specific compatibility mechanisms may evolve, but the security invariant above remains the contract.
