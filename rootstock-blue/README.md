# Rootstock Blue

Rootstock Blue is a Swift toolkit for macOS incident response and offline
forensics. Its command-line interface stores normalized events and custody
records in a `.rsbcase` directory, builds timelines, runs read-only SQL queries,
evaluates local detection rules, and exports JSONL or Markdown.

> Rootstock Blue is alpha software at runtime version `0.4.0-dfir`. The case
> schema, parsers, detection format, and CLI may change between releases. Case checks do not
> certify where evidence came from. Parser compatibility varies by macOS and
> artifact version. A write journal makes interrupted case updates
> fail verification; it does not make a multi-file update atomic or durable
> across power loss.

## What it does

- Create, open, and verify `.rsbcase` packages with a custody log and checksum
  inventory
- Parse supported macOS artifacts from a copied or mounted tree into normalized
  event envelopes
- Merge events into a case timeline and query the case database
- Collect bounded artifact packs from an explicit source tree
- Import core `scan.json` and Red JSONL findings
- Run bundled detection rules against case events
- Produce posture, hardening, timeline, JSONL, and Markdown output
- Import Santa decision logs
- Export an optional family artifact for the core graph
- Inject synthetic fixture events into a case for tests and controlled exercises

Parser coverage includes TCC, quarantine, persistence, browser history,
knowledgeC, recent items, package and application metadata, selected network and
identity artifacts, and other paths enumerated by the registered plugin list.
Coverage is fixture-backed and varies by artifact format and macOS release.

## Requirements

- macOS 14 or later
- Swift 6.2 or later
- A copied or mounted artifact tree for offline parsing
- Full Disk Access when the supplied evidence tree contains paths protected by
  macOS privacy controls

Offline analysis is the supported and tested path. `record inject` reads
synthetic fixture input; it does not connect to Endpoint Security.

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

The bundled synthetic artifact tree is a safe way to try the complete workflow:

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

The Red findings importer expects one JSON object on each non-blank line. It
validates the complete input before writing to the case, so a malformed line
does not leave a partial import. Fix or remove the line and retry.

Export a family artifact for validation or import by the core graph:

```bash
$BIN export family "$CASE" /tmp/rootstock-blue-family.json
uv run --project ../graph --locked rootstock-graph-import-family-export \
  --export /tmp/rootstock-blue-family.json --validate-only
```

These bridges are optional. A Blue case has its own model and does not require
Neo4j or the core collector schema. See the
[product family map](../docs/FAMILY.md).

## Artifact and privacy boundaries

- Keychain, notification, browser, and communication parsers retain selected
  investigative metadata while omitting secret values and message bodies.
- The fixture tree is synthetic. Files with sensitive-looking names contain
  non-secret sentinels or deterministic test data.
- Real case packages, collected files, reports, and browser data are confidential.
- Optional sidecars are installed and configured separately.

## Known limitations

- Parser support is selective and does not replace a complete forensic suite.
- For proprietary or unstable formats, a parser may report only the metadata it
  can handle safely.
- The acquisition package does not unlock FileVault or acquire physical memory
  from Apple silicon.
- Synthetic event injection is profile-driven and offline-only; it does not
  implement Endpoint Security.
- Rootstock Blue is not an EDR, SIEM, MDM, disk imager, or password-recovery
  tool.
- Windows and Linux collection are out of scope.

See [Limitations](docs/limitations.md), [Non-goals](docs/non-goals.md), and
[Architecture](docs/architecture.md).

## Documentation

- [Detection content](Content/detections/README.md)
- [Synthetic event profiles](docs/synthetic-event-profiles.md)
- [Case format](docs/case-package-v0.md)
- [Integration package](docs/integrate/README.md)
- [Santa integration](docs/integrate/santa.md)
- [Fleet and osquery integration](docs/integrate/fleet-osquery.md)
- [Unified Log sidecar](Tools/sidecars/macos-unifiedlogs/README.md)
- [Contributor guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## License

Rootstock Blue is licensed under Apache-2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
