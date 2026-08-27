# GPTHands v1 Upgrade and Rollback

GPTHands packaged installers use side-by-side versioned environments. An upgrade does not overwrite the currently active release in place.

## Layout

Default POSIX layout:

```text
~/.local/share/gpthands/
  install-state.json
  releases/
    1.0.0/
    1.0.1/
~/.local/bin/gpthands
```

Windows uses `%LOCALAPPDATA%\GPTHands` by default.

## Install/upgrade transaction

`install.py install <wheel>` performs:

1. parse and validate GPTHands wheel metadata;
2. create a new version-specific virtual environment if absent;
3. install the local wheel with `pip --no-index --no-deps`;
4. run an import/distribution-version smoke check inside that exact environment;
5. only after success, atomically replace the user launcher;
6. atomically update the owner-local install manifest and preserve the previous version in rollback history.

If creation/install/smoke verification fails, the active launcher is not switched.

## Rollback

From an extracted release bundle:

```bash
python install.py rollback
```

Rollback:

1. selects the most recent previous version from the install manifest;
2. confirms its versioned environment still passes the local smoke check;
3. atomically rewrites the launcher to that environment;
4. updates current/history state.

Release directories are intentionally preserved after launcher uninstall so an operator can recover manually if necessary.

## Offline/security properties

- wheel install is `--no-index --no-deps`;
- runtime package has no third-party Python dependencies;
- install root, bin directory, manifest and launcher symlink replacement are refused;
- new release is smoke-tested before activation;
- previous release is not deleted during upgrade;
- official release bundles are covered by `SHA256SUMS` and build-provenance attestations.

## Recommended operator flow

1. download the platform bundle and checksum file from a verified GitHub Release;
2. verify SHA-256 and GitHub/Sigstore attestation;
3. extract the bundle into a new directory;
4. run `install.sh` or `install.ps1`;
5. run `gpthands doctor --workspace <trusted-workspace>`;
6. if a regression is found, run `python install.py rollback` from the bundle.

## CI proof

The `installer-smoke` CI matrix runs on Ubuntu, macOS and Windows. It builds a synthetic prior release plus the current release, performs:

```text
install old -> install current -> rollback -> install current
```

and then launches `gpthands doctor` through the switched launcher. This tests the actual bootstrap implementation rather than only unit-testing manifest functions.
