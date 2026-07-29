# Rootstock Collector

The Rootstock Collector reads local macOS security metadata and writes one JSON
scan artifact. It does not upload the artifact or perform collection over the
network.

This is alpha software. The output schema, module set, and command behavior may
change before a stable release. The current release procedure does not sign or
notarize the binary archive.

## Requirements

- macOS 14 or later
- Swift 6.3 from Xcode 26.6 when building from source
- Full Disk Access for complete access to protected TCC databases

Collection can complete with recoverable errors. Treat an output containing
warnings as partial and review its `errors` array before analysis.

## Run an archive binary

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
swift test --parallel
```

The source build executable is `.build/release/RootstockCLI`.

## Artifact handling

Scan output can contain hostnames, usernames, application paths, bundle
identifiers, signing metadata, permissions, and security posture. Keep it out
of public issues, source control, and shared screenshots. Redact diagnostics
before sharing them.

## License

The collector is distributed under GPL-3.0. The archive includes the license
text and the repository changelog.
