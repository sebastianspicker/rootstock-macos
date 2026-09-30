# Collector scan: legacy unversioned wire format

`legacy-unversioned.schema.json` defines the collector's current `ScanResult`
document. The collector serializes this model with Swift
`Codable` from `collector/Sources/Models/ScanResult.swift` through
`collector/Sources/Export/JSONExporter.swift`.

The document intentionally has no `schema_version` key. Its absence is part of
the wire contract. Consumers must not infer a schema version from the collector
binary. A breaking change requires a new, explicitly versioned artifact rather
than an in-place change to this schema.

The schema is closed at every modeled object boundary. It describes the
collector output, not cve-scan, Red, Blue, or graph-specific evidence.

`fixtures/valid-collector-encoder-complete.json` is the real `JSONExporter`
output (plus one trailing newline) for a synthetic scan that populates every
optional field and nested type. The collector test `CompleteScanFixtureTests`
fails when the encoder output differs from it, and
`scripts/check-contracts.py` validates it against the schema and requires it to
exercise every schema property except `KeychainItem.sensitivity`, which
consumers accept but the collector never writes. After an intentional wire
change, regenerate it from `collector/` with:

```sh
ROOTSTOCK_REGENERATE_FIXTURES=1 swift test --filter CompleteScanFixtureTests
```
