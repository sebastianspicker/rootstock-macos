# Rootstock Blue architecture

The implemented CLI and libraries share a `.rsbcase` model:

```text
artifact tree or imported event data
    |
    v
parsers and collectors -> normalized EventEnvelope values
    |
    v
.rsbcase package -> timeline, detections, custody, export, reports
```

| Surface | Current alpha status | Privilege |
|---|---|---|
| `rootstock-blue` CLI | Built and fixture-tested | User for offline paths; selected live probes need additional access |
| `RootstockBlueFX` | Offline parser and hardening library | User with access to the mounted or copied artifact tree |
| `RootstockBlueESKit` | Protocols, profiles, mock client, and session injection | Mock-backed by default |
| SwiftUI app, helper, daemon, and system extension sources | Source-only targets outside the default SwiftPM CLI test lane | Platform signing and approval required for live deployment |

The architecture preserves these constraints:

1. The case package is the durable incident artifact.
2. Endpoint Security callbacks must keep bounded work and visible loss counts.
3. The Endpoint Security target must not depend on offline forensics parsers.
4. AUTH or blocking behavior is not enabled by default.
5. Privileged XPC operations use an explicit capability allowlist.
6. Python helpers remain out-of-process workers under `Tools/workers/`.

See [case package](case-package-v0.md),
[Endpoint Security profiles](es-profiles.md), and
[XPC capabilities](xpc-capabilities.md).
