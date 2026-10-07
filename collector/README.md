# Rootstock Collector

The Rootstock Collector reads security metadata from the Mac on which it runs
and writes a single JSON scan. It neither uploads the scan nor collects data
from other hosts.

This is alpha software, so the output schema, available modules, and command
behavior may change before a stable release. Current release archives are not
signed or notarized.

## Requirements

- macOS 14 or later
- Swift 6.3 from Xcode 26.6 when building from source
- Full Disk Access for complete access to protected TCC databases

Full Disk Access and Unix root privileges are separate macOS controls. Running
as root does not grant TCC access by itself. Start without elevation, inspect
the `errors` array, and grant only the access required by the modules you need.

The collector can finish after a recoverable error. If the scan contains
warnings, treat it as partial evidence and review its `errors` array before
analysis.

## Run a release archive

```bash
./rootstock-collector --output scan.json
```

The collector refuses to replace an existing output by default. Use `--force`
only when replacing an existing regular file is intentional. Symlink outputs
are always refused.

Select a comma-separated module subset with `--modules`:

```bash
./rootstock-collector --output tcc.json --modules tcc
./rootstock-collector \
  --output app-security.json \
  --modules entitlements,codesigning,sandbox,quarantine
```

Supported module identifiers are:

```text
tcc, entitlements, codesigning, xpc, persistence, keychain, mdm, groups,
remoteaccess, firewall, loginsessions, authorizationdb, authplugins,
systemextensions, sudoers, processsnapshot, fileacls, shellhooks,
physicalsecurity, activedirectory, kerberos, sandbox, quarantine
```

The `sandbox` and `quarantine` modules require `entitlements`. Run
`./rootstock-collector --help` for the command reference derived from the current
binary.

## Build from source

From the repository's `collector/` directory:

```bash
swift build -c release
```

`sh scripts/verify swift-core` verifies the public build and also runs private
tests when installed locally. Test suites and their fixtures are not published.

The source build executable is `.build/release/RootstockCLI`.

## Artifact handling

A scan can contain hostnames, usernames, application paths, bundle identifiers,
signing metadata, permissions, and security posture. Keep scans out of public
issues, source control, and shared screenshots, and redact diagnostics before
sharing them. The collector creates output files for the owner only, refuses
symlink destinations, and replaces an existing regular file only when you pass
`--force`.

## License

The collector is distributed under GPL-3.0. The archive includes the license
text and the repository changelog.
