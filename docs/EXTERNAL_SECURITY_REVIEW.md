# GPTHands External Security Review Packet

Status: **required before the project should call `v1.0.0` a stable externally reviewed release.**

This document defines a reviewer-ready scope. It does not claim that an independent review has occurred.

## Review objective

Determine whether untrusted model output, repository content or child processes can cross GPTHands owner-controlled security boundaries and obtain authority not explicitly granted by trust state, leases, approvals and OS isolation.

## In-scope security-critical code

- `src/gpthands/policy.py`
- `src/gpthands/approval.py`
- `src/gpthands/audit.py`
- `src/gpthands/locking.py`
- `src/gpthands/sandbox.py`
- `src/gpthands/process_control.py`
- `src/gpthands/windows_sandbox.py`
- `src/gpthands/windows_classic.py`
- `src/gpthands/windows_job.py`
- `src/gpthands/windows_paths.py`
- `src/gpthands/server.py`
- `src/gpthands/limits.py`
- `src/gpthands/ux_server.py`
- `src/gpthands/stable_server.py`
- `src/gpthands/trust.py`
- `src/gpthands/credentials.py`
- `src/gpthands/tunnel.py`
- `src/gpthands/control_ui.py`
- `scripts/release_bootstrap.py`
- release/CI workflows and installer-bundle generation.

## Required attack themes

1. workspace traversal/symlink/reparse escape;
2. policy authority replacement or symlink attack;
3. trust-store forgery;
4. secret-path and environment leakage;
5. approval forgery, replay and cross-process race;
6. action-hash confusion/substitution;
7. process allowlist/risk-classifier bypass;
8. network escape on Linux/macOS/Windows;
9. sandbox child-process escape;
10. timeout descendant survival;
11. Windows AppContainer ACL/reparse/Job Object bypass;
12. local UI CSRF/clickjacking/remote bind/credential leakage;
13. Secure MCP Tunnel profile secret leakage;
14. audit-chain mutation/reordering/truncation limitations;
15. installer symlink/path replacement, downgrade and rollback attacks;
16. supply-chain/reproducibility/attestation weaknesses;
17. MCP modern/legacy confusion that could affect authorization.

## Reviewer acceptance gates

A stable v1 review should at minimum establish that:

- no repository-controlled file can grant a capability;
- unsupported OS isolation fails closed;
- network deny works independently of model intent;
- process-tree cleanup prevents descendants surviving command completion/timeout;
- credentials are not stored in plaintext by GPTHands;
- approval tokens cannot be forged/reused for another workspace/action;
- local UI cannot bind to non-loopback through user input;
- package upgrade cannot silently replace a working release before smoke verification;
- rollback selects a previously installed verified local release;
- known residual risks are accurately documented.

## Reproduction commands

```bash
python -m pip install --no-deps -e .
python -m unittest discover -s tests -v
python -m pip install 'hypothesis==6.165.10'
python -m unittest discover -s tests -p 'test_properties.py' -v
```

Platform CI additionally runs real bubblewrap, macOS Seatbelt and Windows AppContainer integration tests.

## Expected review output

An independent reviewer should provide:

- reviewer identity/organization;
- commit SHA reviewed;
- review dates;
- methodology/tooling;
- findings with severity and reproduction details;
- fixes verified or accepted residual risks;
- final review disposition.

The repository should link that report or advisory from this file before checking the `External security review` roadmap item.

## Disclosure

Security issues should use a private GitHub security advisory/report when repository settings support it. Working exploit details for an unpatched issue should not be filed publicly.
