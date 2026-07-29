# RootstockMacFacts

Shared macOS security vocabulary and read-only helpers for the Core collector,
Rootstock Red, and Rootstock Blue.

This package is licensed under Apache-2.0, consistent with its Rootstock Red
and Rootstock Blue consumers. See [LICENSE](LICENSE).

This source package has no independent runtime version. It follows the source
state of the repository that consumes it.

## Requirements

- macOS 13 or later
- A Swift toolchain compatible with Swift tools 6.0

## Allowed

- Well-known paths (TCC.db, LaunchAgents, BTM, sudoers, PPPC, system extensions)
- TCC service id → display name catalog
- Launchd plist discovery / programArguments extraction
- Optional live host posture probes (SIP / Gatekeeper / FileVault signals)

## Forbidden

- Product serializers (`ScanResult`, `Finding`, `EventEnvelope`)
- Neo4j / case SQLite / network clients
- Keychain secret extraction or TCC.db row dumping policy (callers own depth)

## Consumers

Path dependency from sibling packages:

```swift
.package(path: "../packages/RootstockMacFacts")
// or from collector/: path: "../packages/RootstockMacFacts"
```

## Build and test

```bash
cd packages/RootstockMacFacts
swift build
swift test --parallel
```

The package builds the `RootstockMacFacts` library product. It has no
executable, network client, or standalone artifact format.
