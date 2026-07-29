# Rootstock Blue

Rootstock Blue is a Swift package for macOS incident-response and offline
forensic workflows. Its CLI stores normalized events and custody records in a
`.rsbcase` case package, supports timeline and SQL review, evaluates local
detection content, and writes JSONL or Markdown output.

> Alpha status: the runtime label is `0.4.0-dfir` and the bundle marketing
> version is `0.4.0`. The case schema, parsers, detection format, and CLI may
> change. The package does not claim evidentiary certification or compatibility
> with every macOS artifact version.

## Current capabilities

- Create, open, and verify `.rsbcase` packages with custody hashes
- Parse fixture-backed offline macOS artifacts into normalized event envelopes
- Merge events into a case timeline and query the case database
- Collect bounded artifact packs from an explicit source tree
- Import core `scan.json` and Red JSONL findings
- Run bundled detection rules against case events
- Produce posture, hardening, timeline, JSONL, and Markdown output
- Import Santa decision logs and expose limited interchange helpers
- Export an optional family artifact for the core graph
- Inject mock Endpoint Security event data into a case for tests and controlled
  exercises

Parser coverage includes TCC, quarantine, persistence, browser history,
knowledgeC, recent items, package and application metadata, selected network and
identity artifacts, and other paths enumerated by the registered plugin list.
Coverage is fixture-backed and varies by artifact format and macOS release.

## Requirements

- macOS 14 or later
- Swift 6.2 or later
- A copied or mounted artifact tree for offline parsing
- Full Disk Access and system approvals for applicable live collection paths

The default tested path is offline analysis. Live Endpoint Security operation
also requires signing, entitlements, and user or MDM approval.

## Build and test

Run these commands from `rootstock-blue/`:

```bash
make bootstrap
make test
make content-validate
make check-non-goals
swift build --product rootstock-blue
```

The debug CLI is `.build/debug/rootstock-blue`.

## Case workflow

The bundled fixture provides a privacy-safe starting point:

```bash
BIN=.build/debug/rootstock-blue
FIX=Fixtures/artifacts/macos_sample
CASE=/tmp/rootstock-blue-demo.rsbcase

$BIN case create "$CASE" --name synthetic-demo
$BIN parse "$FIX" --case "$CASE"
$BIN collect post-incident-ir --case "$CASE" --source "$FIX" --offline
$BIN ir posture --case "$CASE" --source "$FIX"
$BIN ir harden --case "$CASE" --source "$FIX"
$BIN detect run --ruleset samples --case "$CASE"
$BIN timeline "$CASE" --limit 40
$BIN report markdown "$CASE" /tmp/rootstock-blue-report.md
$BIN case verify "$CASE"
```

The one-step offline path is:

```bash
$BIN ir triage --case "$CASE" --source "$FIX" --offline
```

Case packages and reports can contain sensitive host, identity, browser,
software, and security-control metadata. Do not commit real output.

## Optional family bridges

Import synthetic core or Red artifacts into a case:

```bash
$BIN import scan-json ../examples/demo-scan.json --case "$CASE"
$BIN import findings-jsonl ../rootstock-red/Fixtures/sample_findings.jsonl \
  --case "$CASE"
```

Export a family artifact for validation or import by the core graph:

```bash
$BIN export family "$CASE" /tmp/rootstock-blue-family.json
python3 ../graph/import_family_export.py \
  --export /tmp/rootstock-blue-family.json --validate-only
```

These bridges are optional. Blue does not use Neo4j or the core collector
schema as its default case model. See [Product family](../docs/FAMILY.md).

## Artifact and privacy boundaries

- Keychain, notification, browser, and communication parsers are designed to
  retain metadata required for investigation without exporting secret values
  or message bodies.
- The fixture tree is synthetic. Files with sensitive-looking names contain
  non-secret sentinels or deterministic test data.
- Real case packages, collected files, reports, browser data, and live Endpoint
  Security output are confidential.
- Optional sidecars are not bundled unless explicitly documented.

## Known limitations

- Parser support is selective and does not replace a complete forensic suite.
- ZIP archive import is disabled. Prepare an already-extracted collection tree
  in a separate, isolated process, then use `parse` with that tree.
- Proprietary or unstable artifact formats may use bounded metadata-only
  handling.
- The acquisition package does not unlock FileVault or acquire physical memory
  from Apple silicon.
- Live Endpoint Security coverage is not equivalent to the offline test matrix.
- Rootstock Blue is not an EDR, SIEM, MDM, disk imager, or password-recovery
  tool.
- Windows and Linux collection are out of scope.

See [Limitations](docs/limitations.md), [Non-goals](docs/non-goals.md), and
[Architecture](docs/architecture.md).

## Fixture layout and detections

- [Fixture layout](Fixtures/artifacts/macos_sample/FORENSICS_LAYOUT.md)
- [Detection content](Content/detections/README.md)
- [Case format](docs/case-package-v0.md)
- [Integration notes](docs/integrate/)
- [Security policy](SECURITY.md)

## License

Rootstock Blue is licensed under Apache-2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
