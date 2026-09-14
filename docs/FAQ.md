# Frequently asked questions

## General

### What is Rootstock?

Rootstock collects macOS security metadata and connects it in a graph. You
can inspect permissions, entitlements, signing, services, and persistence
alongside modeled exposure paths. Red, Blue, and cve-scan provide separate
assessment, incident-analysis, and scanning workflows.

### Can I use existing SharpHound or OpenGraph data?

The graph package can import selected SharpHound/OpenGraph artifacts. Check
the [graph README](../graph/README.md) for the supported commands. Import
support does not imply that all schemas or features from another tool are
available.

### What is Rootstock intended for?

Rootstock is for authorized security assessment and research. The collector
reads local metadata and writes a scan file. Rootstock Red keeps its
potentially mutating lab actions in a separate executable with explicit dry-run
controls. See [THREAT_MODEL.md](THREAT_MODEL.md).

### What about rootstock-red and rootstock-blue?

Red handles assessment and separately controlled lab exercises. Blue handles
offline incident cases. Core is the collector and graph workflow. See
[FAMILY.md](FAMILY.md) for roles and supported artifact handoffs.

## Collector

### Why does the TCC scanner return 0 grants?

First inspect the scan's `errors` array. A zero count can mean that the
collector could not read the protected database. If the error reports missing
Full Disk Access, grant it to the terminal application, then run the collector
as the user whose TCC database you intend to inspect:

```bash
collector/.build/release/RootstockCLI --output scan.json
```

Other modules may report that elevation is required. Review the output
`errors` array before deciding whether a separate elevated scan is necessary.

### Why are some apps missing entitlements?

An app may have no entitlements, or the collector may have failed to read
them. Inspect the scan errors to distinguish missing data from an extraction
failure. The collector records recoverable errors and continues the scan.

### Can I scan a remote Mac?

Not directly. Run the collector on the target Mac, transfer the JSON file, and
import it into Neo4j on the analysis workstation.

## cve-scan

### What is `modules/cve-scan/`?

It is Rootstock's scoped CVE evidence module. It collects package, service, TLS,
web, container, and configuration evidence from an explicit scope file, then
writes local reports plus `rootstock-export.json` for graph import.

### Does Rootstock run cve-scan automatically?

No. Run cve-scan separately, then import the prebuilt artifact:

```bash
uv run --project graph --locked \
  rootstock-graph-import-cve-scan --input /path/to/rootstock-export.json
```

Or include the export in a collector pipeline run. Both commands use your
configured Neo4j credentials:

```sh
bash graph/pipeline.sh /path/to/scan.json \
  --cve-scan-export /path/to/rootstock-export.json
```

### Can I commit cve-scan outputs?

No. Real `scan.json`, `rootstock-export.json`, reports, caches, rendered
viewers, screenshots, package inventories, and CVE scan outputs can contain
infrastructure data. Keep them local. The checked-in
`examples/cve-scan-export.json` file is synthetic.

### Which local artifacts belong in commits?

Commit only files required to build, test, operate, maintain, or understand the
project. Keep private data, machine-specific state, and reproducible output in
a private directory outside the checkout. `.gitignore` covers common names and
generated directories, but it is not a confidentiality control.

## Graph pipeline

### Which database setup do I need?

The repository includes a local Neo4j 5.x Compose service for the graph
pipeline. The authenticated API also needs a distinct read-only account whose
privileges it can verify. Check [Configuration](CONFIGURATION.md) before
starting the API; a working import connection alone is not sufficient.

### Can I import scans from multiple Macs?

Yes. Each import is tagged with `scan_id`, and the importer preserves per-host
installations. Import multiple JSON files into the same Neo4j instance with
`rootstock-graph-merge-scans` or repeated `rootstock-graph-import-scan` runs.

### Why do some queries return no results?

A query returns only what matches the imported evidence and inference rules.
For TCC queries, check whether the collector could read the relevant database.
Also check that you imported the intended scan and ran inference. An empty
result does not establish that the host is safe.
