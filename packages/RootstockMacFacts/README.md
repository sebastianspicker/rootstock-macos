# RootstockMacFacts

RootstockMacFacts provides shared macOS security vocabulary and read-only
helpers for the Core collector, Rootstock Red, and Rootstock Blue.

This package is licensed under Apache-2.0, consistent with its Rootstock Red
and Rootstock Blue consumers. See [LICENSE](LICENSE).

The package has no independent runtime version. Its version is the source
revision used by each consumer.

## Requirements

- macOS 13 or later
- Swift 6.2 or later

## Package scope

- Well-known paths for TCC databases, LaunchAgents, BTM, sudoers, PPPC, and
  system extensions
- A catalog that maps TCC service identifiers to display names
- Launchd property-list discovery and `ProgramArguments` extraction
- Optional live posture checks for SIP, Gatekeeper, and FileVault signals

## Outside its scope

- Product serializers (`ScanResult`, `Finding`, `EventEnvelope`)
- Neo4j / case SQLite / network clients
- Keychain secret extraction and product policy for reading TCC rows; each
  caller decides how much data to collect

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
```

`sh scripts/verify swift-family` verifies the public build and also runs private
tests when installed locally. Test suites and their fixtures are not published.

The package builds the `RootstockMacFacts` library product. It has no
executable, network client, or standalone artifact format.
