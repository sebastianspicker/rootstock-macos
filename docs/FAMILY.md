# Rootstock product family

Use Rootstock's products independently or pass files between them for further
analysis. Each product keeps its own commands, data model, and storage.
[DD-010](design-docs/product-family.md) explains this design.

## Choose a product

| Component | Primary operation | Primary artifact |
| --- | --- | --- |
| Core collector and graph | Local inventory, Neo4j import, inference, reports, and viewer | Legacy-unversioned `scan.json`, Neo4j data |
| cve-scan | Explicitly scoped package, service, web, TLS, and IaC evidence | `rootstock-export.json`, schema v7 |
| Rootstock Red | Read-only assessment and separately gated lab | Findings or project bundle |
| Rootstock Blue | Offline artifact parsing, case management, detections, and reports | `.rsbcase` |
| RootstockMacFacts | Shared read-only paths, catalogs, and parsers | Swift library values |

## Shared file formats

| Use case | Producer → consumer | Format definition |
| --- | --- | --- |
| Collector scan | Collector → graph / Blue scan import | `contracts/collector-scan/legacy-unversioned.schema.json` |
| CVE evidence | cve-scan → graph | `contracts/cve-scan-export/v7/schema.json` |
| Family graph export | Red or Blue → graph | `contracts/family-open-export/v1/schema.json` |
| Findings handoff | Red → Blue | `contracts/red-findings-to-blue-jsonl/v1/` |

The cve-scan module's internal `ScanResult` is not the collector host scan.
Cross-product bridges use checked-in schemas and synthetic fixtures, not direct
Swift or Python type sharing. Run `sh scripts/verify graph` to validate all
shared schemas, fixtures, and importer checks.

## Pass data between tools

- Collector scan to Blue case: `rootstock-blue import scan-json <scan.json> --case <case>`.
- Red findings JSONL to Blue case: `rootstock-blue import findings-jsonl <file> --case <case>`.
- Red or Blue family export to graph: use the installed
  `rootstock-graph-import-family-export` command.
- cve-scan export to graph: select the completed export through
  `graph/pipeline.sh --cve-scan-export <file>`.

Run exports and imports explicitly when you need them. Graph import records
where each artifact came from. Passwords, private keys, and token values must
stay out of these files.

Similar concepts have different evidence depth. For example, the collector can
inventory readable TCC grants, Red assesses access preconditions, and Blue
parses offline TCC artifacts into events and detections. Do not describe one
product's output as evidence collected by another.

Technique identifiers shared across documentation and product content are in
[`references/technique-catalog.yaml`](references/technique-catalog.yaml) and
are checked by the Swift-family lane.
