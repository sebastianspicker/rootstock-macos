# DD-011: File exchange between products

Status: Accepted; optional imports and exports are implemented
Date: 2026-07-16

## Context

[DD-010](product-family.md) keeps collector/graph, Rootstock Red, and Rootstock
Blue as separate products. Operators still need explicit file transfers, such
as importing a collector snapshot into a Blue case or attaching Red findings
to an incident-response package, without coupling Swift packages or combining
schemas.

[DD-009](cve-scan-artifact-bridge.md) establishes the pattern: produce a
versioned JSON artifact; validate allowlists; import with provenance.

## Decision

1. Bridges are optional commands and are not required for default pipelines.
2. Versioned exports declare `schema_version`; consumers reject unsupported
   versions. The collector scan remains a legacy, unversioned format, and the
   Red findings handoff follows its documented JSONL record contract.
3. Every imported record identifies its source as `collector`,
   `rootstock-red`, `rootstock-blue`, or `cve-scan`.
4. Prefer JSON artifacts over importing another product’s Swift/Python types.
5. Only synthetic fixtures belong in Git; real host output stays private.

### Bridges

| Bridge | Producer | Consumer | Status |
|--------|----------|----------|--------|
| scan.json → case | collector | rootstock-blue `import scan-json` | Implemented |
| findings JSONL → case | rootstock-red | rootstock-blue `import findings-jsonl` | Implemented |
| family open-export → Neo4j | red `export-family` / blue `export family` | `rootstock-graph-import-family-export` (schema v1) | Implemented; Host, Finding, Protection, and LaunchItem nodes |

See the synthetic [Red export](../../examples/family-export-red.json) and
[Blue export](../../examples/family-export-blue.json) for complete examples.

### What remains separate

Blue continues to manage cases, and Red continues to write findings. Exporting
a file does not turn either product into a graph client or share mutable state.

## Usage

### Import into a Blue case

```bash
rootstock-blue import scan-json ./scan.json --case ./incident.rsbcase
rootstock-blue import findings-jsonl ./findings.jsonl --case ./incident.rsbcase
```

### Graph consumer

`rootstock-graph-import-family-export` accepts only the documented Host,
Finding, Protection, and LaunchItem node types. It preserves the source and
marks imported records with `family_export=true`. OpenGraph exports keep Red,
Blue, and cve-scan finding types distinct.

## Consequences

- Bridge code lives next to the consumer (Blue import modules and the graph
  package) with synthetic fixtures. The canonical schemas and fixtures
  are under `contracts/`.
- Technique catalog IDs may appear as optional fields on findings/events for
  cross-product mapping; they are not required for import validity.
- The `graph` and `swift-family` verification lanes check schemas,
  producer exports, consumer validation, stable identifiers, and provenance.

## See also

- [Product family map](../FAMILY.md)
- [DD-009: cve-scan Artifact Bridge](cve-scan-artifact-bridge.md)
- [DD-010: Product Family Architecture](product-family.md)
