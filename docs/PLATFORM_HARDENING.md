# GPTHands Platform Hardening Strategy

This document defines the next OS-isolation boundary without weakening the current fail-closed model.

## Security invariant

A platform backend is only considered usable when it can enforce all of the following independently of model intent:

1. workspace-scoped filesystem visibility;
2. read-only workspace when no live write lease exists;
3. no host credential/home-directory visibility by default;
4. network deny-by-default;
5. bounded process lifetime/resources;
6. no silent fallback to an unsandboxed process when `require_os_sandbox=true`.

A backend that only limits CPU/memory or only changes process integrity level is **not** sufficient.

## macOS

### Current v0.2/v0.3 backend

`sandbox-exec`/Seatbelt remains the low-overhead backend where it is present. CI executes real read/write isolation tests on a GitHub macOS runner. The project treats this as a compatibility backend because Apple has deprecated the public `sandbox-exec` interface.

### Durable successor

The preferred long-term boundary is a dedicated sandbox helper with a VM/container isolation option:

```text
GPTHands MCP process
        |
        | signed request + explicit workspace grant
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

The helper contract must expose capabilities rather than arbitrary host mounts. The host-side GPTHands process remains responsible for policy, leases, approval tokens, audit, and change review.

A native App-Sandbox-entitled helper may be evaluated for low-latency commands, but it is not accepted merely because it has an entitlement; dynamic workspace access, child-process behavior, and network denial must be integration-tested. VM/container isolation is the safer fallback when those guarantees cannot be demonstrated.

### Migration rule

The Seatbelt backend stays supported only while its real integration tests pass. If a future macOS image removes or changes it, GPTHands must fail closed until a successor backend passes equivalent tests. There is no `policy-only` automatic downgrade.

## Windows

### Current v0.3 behavior

Windows process execution with `require_os_sandbox=true` intentionally fails closed. CI verifies that behavior. Job Objects or low-integrity tokens alone are not accepted as the main boundary because they do not provide sufficient filesystem and network isolation.

### AppContainer staged-workspace design

The target Windows backend is an AppContainer process operating on a **staged workspace**, not directly on the user's real repository:

```text
real repository
     |
     | policy-filtered copy
     v
private staging directory
     |
     | ACL: generated AppContainer SID only
     v
AppContainer process
  - no network capabilities by default
  - no host home/credential access
  - Job Object resource limits
     |
     | verified change set
     v
GPTHands preview/apply path
     |
     v
real repository
```

Key properties:

- never grant AppContainer ACLs to the user's real home or repository tree;
- create a unique/private staging root per action or lease scope;
- omit network capabilities unless a NETWORK-classified action has a live lease and required approval;
- combine AppContainer with a Job Object for timeout/process-tree cleanup/resource limits;
- copy changes back only through GPTHands path validation and preview/apply controls;
- reject symlinks/reparse-point escapes during staging and synchronization;
- delete staging state after use and fail closed if cleanup or ACL setup cannot be verified.

### Acceptance tests required before enabling Windows execution

1. process cannot read a marker file in the user's real home;
2. process cannot connect to loopback or internet without network capability;
3. read-only staged workspace rejects writes;
4. write-enabled staging cannot change files outside staging;
5. reparse points cannot escape staging;
6. child processes remain in the Job Object/AppContainer boundary;
7. timeout terminates the full process tree;
8. synchronized changes still pass GPTHands secret/path policy.

Until these tests are implemented and green on Windows CI, Windows remains fail-closed for generic process execution.
