# DD-010: Separate products, shared facts

Status: Accepted
Date: 2026-07-16

## Context

The products inspect related macOS data but answer different questions.
Their commands and output formats reflect those differences:

| Product | Role | Primary artifact |
|---------|------|------------------|
| Core (`collector/` + `graph/`) | Collect host metadata and inspect modeled paths | `scan.json` → Neo4j |
| `modules/cve-scan/` | Scan targets declared in a scope file | Reports and `rootstock-export.json` |
| `rootstock-red/` | Read-only assessment and separate lab exercises | `Finding` JSONL/SARIF/MD |
| `rootstock-blue/` | Offline incident analysis | `.rsbcase` + `EventEnvelope` |

They need consistent names for shared concepts without forcing case records,
collector scans, and assessment findings into one format.

## Decision

1. Products remain separate pipelines. Do not merge red, blue, and collector
   into a single binary, schema, or runtime.
2. Share the parts that have the same meaning across products:
   - Family documentation (`docs/FAMILY.md`)
   - Paths, TCC service names, and discovery helpers in RootstockMacFacts
   - A cross-product technique catalog with stable family IDs
   - Optional, versioned artifact bridges (same pattern as
     [DD-009 cve-scan Artifact Bridge](cve-scan-artifact-bridge.md))
3. Root documentation describes the Core collector and graph workflow and
   links sibling products as related monorepo products without claiming a
   shared runtime or artifact model.

### Boundaries

| Boundary | Reason |
|----------|--------|
| Neo4j path traversal stays in `graph/` | Requires stable entity IDs and edge vocabulary from `ScanResult` |
| Red non-prompting TCC default | Avoid prompting for access or dumping TCC.db rows by default |
| Lab changes only in `rootstock-red-lab` | The assessment executable must not perform lab changes |
| Blue case custody (`.rsbcase`) | A case package has different integrity and event semantics from a graph snapshot or findings file |
| No secret extraction | Architectural invariant across the family (DD-004) |
| Graph imports cve-scan through `rootstock-export.json` | Keeps scanner and Neo4j decoupled |

## Rationale

Some concepts repeat, but the tools collect different evidence. The collector
parses readable host facts for graph inventory. Red performs authorized
assessment without interactive prompts. Blue works with offline evidence trees
and timeline custody. Shared path constants, service registries, and optional
JSON contracts reduce drift while preserving these distinct purposes.

## Alternatives Considered

- One executable and one schema: rejected because the products have different
  safety controls and output models.
- Documentation without shared facts: rejected because path and TCC name lists
  would drift between products.

## Consequences

- Repository and component documentation link the related products and their
  supported contracts.
- Shared Swift code lives in neutral packages (for example
  `packages/RootstockMacFacts`) with no dependency on `ScanResult`,
  `Finding`, or `EventEnvelope`.
- Cross-product handoffs use versioned JSON artifacts, not SPM imports of
  another product’s core types.
- Technique IDs in `docs/references/technique-catalog.yaml` map graph queries,
  red findings, and blue detections without a shared runtime.

## See also

- [Product family map](../FAMILY.md)
- [DD-009: cve-scan Artifact Bridge](cve-scan-artifact-bridge.md)
- [Family artifact bridges](family-artifact-bridges.md)
