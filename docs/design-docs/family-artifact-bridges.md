# DD-011: Family Artifact Bridges

Status: Accepted (design); implementations optional and versioned
Date: 2026-07-16

## Context

[DD-010](product-family.md) keeps collector/graph, rootstock-red, and
rootstock-blue as separate products. Operators still need controlled handoffs
(for example: import a collector snapshot into a blue case, or attach red
findings to an IR package) without coupling SPM packages or collapsing schemas.

[DD-009](cve-scan-artifact-bridge.md) already proves the pattern: produce a
versioned JSON artifact; validate allowlists; import with provenance.

## Decision

1. Bridges are optional tools/subcommands - not required for default pipelines.
2. Each bridge declares `schema_version` and fails closed on mismatch.
3. Provenance is mandatory: `source` ∈
   `collector` | `rootstock-red` | `rootstock-blue` | `cve-scan`.
4. Prefer JSON artifacts over importing another product’s Swift/Python types.
5. Synthetic fixtures only in git; real host outputs stay ignored.

### Bridges

| Bridge | Producer | Consumer | Status |
|--------|----------|----------|--------|
| scan.json → case | collector | rootstock-blue `import scan-json` | Shipped |
| findings JSONL → case | rootstock-red | rootstock-blue `import findings-jsonl` | Shipped |
| family open-export → Neo4j | red `export-family` / blue `export family` | `graph/import_family_export.py` (schema v1) | Shipped (optional, allowlisted Host/Finding/Protection/LaunchItem) |

Synthetic fixtures: `examples/family-export-red.json`, `examples/family-export-blue.json`.

### Non-goals

- Making blue a Neo4j viewer
- Making red emit full graph `ScanResult` by default
- Shared mutable runtime between products

## Usage

### Blue CLI (examples)

```bash
rootstock-blue import scan-json ./scan.json --case ./incident.rsbcase
rootstock-blue import findings-jsonl ./findings.jsonl --case ./incident.rsbcase
```

### Graph consumer

`graph/import_family_export.py` validates allowlisted Host / Finding /
Protection / LaunchItem nodes and MERGEs them with `source` provenance and
`family_export=true`. OpenGraph/viewer mapping
(`graph/opengraph_export.py`: `resolve_node_type_info`,
`family_export_to_opengraph`) maps those findings to `rs_RedFinding` /
`rs_BlueFinding` and host→finding edges to `rs_RedHasFinding` /
`rs_BlueHasFinding` so they stay distinct from cve-scan `rs_CveFinding`.

## Consequences

- Bridge code lives next to the consumer (blue import modules; graph import
  scripts) with golden synthetic fixtures.
- Technique catalog IDs may appear as optional fields on findings/events for
  purple handoff; they are not required for import validity.
- Default CI for core Rootstock remains collector/graph/cve-scan; bridge tests
  run in product packages that implement them.

## See also

- [Product family map](../FAMILY.md)
- [DD-009: cve-scan Artifact Bridge](cve-scan-artifact-bridge.md)
- [DD-010: Product Family Architecture](product-family.md)
