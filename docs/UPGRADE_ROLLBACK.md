# GPTHands v1 Upgrade and Rollback

GPTHands packaged installers use side-by-side versioned environments. An upgrade does not overwrite the currently active release in place.

## Layout

Default POSIX layout:

```text
~/.local/share/gpthands/
  install-state.json
  releases/
    1.0.0/
      .gpthands-release.json
    1.0.1/
      .gpthands-release.json
~/.local/bin/gpthands
```

Windows uses `%LOCALAPPDATA%\GPTHands` by default.

Each packaged ZIP also contains:

```text
WHEEL.SHA256
BUNDLE-MANIFEST.json
install.py
install.sh or install.ps1
<gpthands wheel>
```

The embedded wheel digest protects **bundle-to-wheel consistency**. It does not authenticate a maliciously replaced entire ZIP, so the ZIP itself must still be verified against the separately published release `SHA256SUMS` / GitHub-Sigstore attestation from a trusted release page.

## Install/upgrade transaction

`install.py install <wheel> --sha256 <trusted-wheel-digest>` performs:

1. lexically canonicalize managed paths without resolving away a final symlink;
2. refuse a symlink wheel, install root, bin directory, `releases/` directory or version target;
3. verify the wheel SHA-256 **before** inspecting or installing it;
4. parse and validate GPTHands wheel metadata;
5. reject same-version substitution when the manifest already binds that version to a different digest;
6. create a new version-specific virtual environment if absent;
7. install the local wheel with `pip --no-index --no-deps`;
8. run an import/distribution-version smoke check inside that exact environment;
9. write `.gpthands-release.json` binding that installed version to the verified wheel digest;
10. only after success, atomically replace the user launcher;
11. atomically update the owner-local install manifest and preserve the previous version + digest in rollback history.

If digest verification, creation, install or smoke verification fails, the active launcher is not switched.

The platform bundle wrappers automatically read their embedded `WHEEL.SHA256` and pass it to `install.py`. Operators should verify the **ZIP** itself first using release metadata obtained separately from the trusted GitHub Release page.

## Rollback

From an extracted release bundle:

```bash
python install.py rollback
```

Rollback:

1. selects the most recent previous version from the install manifest;
2. requires a recorded wheel digest for that version;
3. checks the version-specific `.gpthands-release.json` marker against that digest;
4. confirms its environment still passes the local smoke check;
5. atomically rewrites the launcher to that environment;
6. updates current/history state.

A versioned environment with a missing/mismatched digest marker is refused for automatic rollback instead of being trusted only because its directory name/version metadata looks valid.

Release directories are intentionally preserved after launcher uninstall so an operator can recover manually if necessary.

## Offline/security properties

- wheel install is `--no-index --no-deps`;
- runtime package has no third-party Python dependencies;
- wheel SHA-256 is mandatory for packaged install;
- same-version wheel substitution is refused;
- each installed version is locally bound to its wheel digest;
- install root, bin directory, `releases/`, version target, manifest and launcher symlink replacement are refused;
- new release is smoke-tested before activation;
- rollback requires both digest binding and smoke verification;
- previous release is not deleted during upgrade;
- official release bundles are covered by external `SHA256SUMS` and build-provenance attestations.

This protects against accidental corruption and model/workspace attempts to redirect installer-managed paths. It does not defend against a host-user or administrator who can rewrite both GPTHands state and binaries; host-account compromise is outside the local installer trust boundary.

## Recommended operator flow

1. download the platform bundle and checksum/attestation metadata from a verified GitHub Release;
2. verify the **bundle ZIP** SHA-256 and GitHub/Sigstore provenance;
3. extract the bundle into a new directory;
4. run `install.sh` or `install.ps1` — the wrapper verifies the embedded wheel digest before install;
5. run `gpthands doctor --workspace <trusted-workspace>`;
6. if a regression is found, run `python install.py rollback` from the bundle.

## CI proof

The `installer-smoke` CI matrix runs on Ubuntu, macOS and Windows. It builds a synthetic prior release plus the current release, performs:

```text
verified install old -> verified install current -> digest-bound rollback -> verified install current
```

and then launches `gpthands doctor` through the switched launcher. The security regression suite additionally checks digest mismatch, malformed digest metadata, symlink wheel/release paths and same-version digest substitution.
