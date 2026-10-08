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
physicalsecurity, activedirectory, kerberos, sandbox, quarantine,
networklisteners, trustsettings, browserextensions, installedpackages
```

The `sandbox` and `quarantine` modules require `entitlements`. Run
`./rootstock-collector --help` for the command reference derived from the current
binary.

## What the collector records

Beyond inventory, the collector records the facts the graph needs to tell real
exposure from noise:

- Code signing: Hardened Runtime, Library Validation, ad-hoc signature,
  certificate chain, and the Gatekeeper assessment from `spctl`
  (`is_notarized`, `gatekeeper_assessment`). An `spctl` failure leaves the
  status unknown; only an explicit rejection means "not notarized".
- Electron: whether the `RunAsNode` fuse is enabled (`electron_run_as_node`).
  Apps that disable the fuse are not reported as injectable through
  `ELECTRON_RUN_AS_NODE`.
- Launch items: owner and writability of plist and program, plus the program's
  signing team and identifier (`program_team_id`, `program_signing_id`) so a
  helper in `/Library/PrivilegedHelperTools` can be linked to the app that
  installed it.
- Launch item details: program arguments (at most 16; arguments are recorded
  with secret-looking values redacted: the value after flags such as
  `--password`/`--token`/`--api-key`, `key=value` values with such keys, URL
  credentials, queries and fragments, and long hex or base64-like runs become
  `<redacted>`), environment variable
  names, and the values of `DYLD_*` variables only (launchd-based library
  injection); triggers (interval, calendar, watch paths, sockets, Mach services,
  launch events), session type, `Disabled`, and whether launchd has the label
  loaded (`launchctl list` / `launchctl print system`; unknown when launchctl
  is unavailable).
- Launch item programs: existence, SHA-256 (absolute paths only; regular files
  up to 64 MiB outside `/System`) and the plist modification time. Applications also record their
  main executable and, for third-party apps, its SHA-256.
- Further persistence: launch agents, daemons and login items embedded in app
  bundles (`Contents/Library/...`, with `bundle_path`), and loginwindow
  `LoginHook` / `LogoutHook` scripts.
- Firewall: live state from `socketfilterfw` (enabled, stealth mode, automatic
  allow rules, per-app rules), with the legacy ALF plist as a fallback.
- Network listeners: listening TCP and bound UDP sockets from `netstat -anv`,
  with the owning process, user and, for processes inside a discovered app,
  its bundle ID. `*` (any address) is not counted as loopback.
- Certificate trust settings: certificates with explicit trust settings in the
  user and admin domains (SHA-256, subject, issuer, strongest trust result,
  expiry). Apple's built-in roots are not collected.
- Browser extensions: Chromium-family browsers, Firefox and Safari, with
  permissions, host permissions, store origin, enabled state and install
  location. Only manifests and profile settings are read, never browsing data.
- Installed packages: installer receipts from `/var/db/receipts`.
- Kernel extensions: third-party kexts loaded according to `kmutil showloaded`.
- Host settings (always collected): guest, auto-login and root accounts, Remote
  Apple Events and Remote Management, Software Update automation, XProtect,
  XProtect Remediator and MRT versions, DNS servers, enabled proxies and
  non-default `/etc/hosts` entries.
- SSH: `PermitRootLogin`, password and public-key authentication, the number of
  `authorized_keys` entries and whether `ForwardAgent yes` is set. Key material
  is never read.
- Quarantine: the download host of each quarantined app from the LaunchServices
  quarantine events database (`origin_host`); the full URL is not recorded.
- Critical files: a file is "writable by non-root" when it is world- or
  group-writable, carries a write ACL, or is owned by someone other than its
  expected owner (root for system paths, the home-directory user under
  `/Users/<name>`). A user's own dotfiles and login keychain are not findings.

At the end of a run the collector prints a coverage summary that groups
warnings by source and names the action that closes the gap, for example
granting Full Disk Access to the terminal that runs it, rerunning with
`sudo` for sudoers, per-user crontabs and the login-item database, or running
as the logged-in user in a GUI session for trust settings and browser
extensions.

## Build from source

From the repository's `collector/` directory:

```bash
swift build -c release
```

`sh scripts/verify swift-core` verifies the public build and also runs private
tests when installed locally. Test suites and their fixtures are not published.

The source build executable is `.build/release/RootstockCLI`.

## Artifact handling

A scan can contain hostnames, the Mac's hardware UUID (`hardware_uuid`, used to
tell apart Macs that share a hostname), usernames, application paths, bundle identifiers,
signing metadata, permissions, and security posture. Keep scans out of public
issues, source control, and shared screenshots, and redact diagnostics before
sharing them. The collector creates output files for the owner only, refuses
symlink destinations, and replaces an existing regular file only when you pass
`--force`.

## License

The collector is distributed under GPL-3.0. The archive includes the license
text and the repository changelog.
