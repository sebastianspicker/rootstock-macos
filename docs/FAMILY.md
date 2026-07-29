# Rootstock product family

This repository contains related macOS security components with separate build
graphs and artifacts. They share terminology and a small Swift facts package.
They are not one executable and do not exchange data unless an operator invokes
an explicit bridge.

The architecture decision is recorded in
[DD-010](design-docs/product-family.md).

## Component boundaries

| Component | Primary operation | Primary artifact |
|---|---|---|
| Core collector and graph | Local host inventory, Neo4j import, relationship inference, queries, reports, and viewer | `scan.json` and Neo4j data |
| cve-scan | Explicitly scoped software, service, web, TLS, and IaC evidence for the Core graph | `rootstock-export.json` schema v7 |
| Rootstock Red | Read-only host assessment and a separately built, gated lab executable | Findings or project bundle |
| Rootstock Blue | Offline macOS artifact parsing, case management, detections, and reports | `.rsbcase` case package |
| RootstockMacFacts | Shared paths, catalogs, and read-only parsers | Swift library values |

The cve-scan module is part of the Core analysis path. The Red and Blue packages
retain independent versions and source-only release procedures.

## Commands and contracts

| Use case | Command outline | Contract |
|---|---|---|
| Collect and analyze a host | `RootstockCLI --output scan.json`, then `graph/pipeline.sh scan.json` | `collector/schema/scan-result.schema.json` |
| Add cve-scan evidence | `cve-scan scan ...`, then pipeline `--cve-scan-export` | `rootstock-export.json` schema v7 |
| Run Red assessment | `swift run rootstock-red audit --format jsonl` | `rootstock-red/docs/FINDING_SCHEMA.md` |
| Create a Blue case | `swift run rootstock-blue case create <path>` | `rootstock-blue/docs/case-package-v0.md` |

cve-scan's internal Python `ScanResult` is a module scan record. It is not the
Core collector's host `ScanResult`.

## Explicit interoperability

Validate a Red or Blue family export without connecting to Neo4j:

```bash
python3 graph/import_family_export.py \
  --export examples/family-export-red.json --validate-only
python3 graph/import_family_export.py \
  --export examples/family-export-blue.json --validate-only
```

Omit `--validate-only` only when importing into an operator-controlled Neo4j
instance. Imported findings retain their `rootstock-red` or `rootstock-blue`
source. The graph maps them to component-specific finding node and edge types.

Other implemented optional bridges are:

| Direction | Command |
|---|---|
| Red project to family export | `rootstock-red export-family --project <dir> --output <file>` |
| Blue case to family export | `rootstock-blue export family <case> <file>` |
| Core scan to Blue case | `rootstock-blue import scan-json <scan.json> --case <case>` |
| Red findings to Blue case | `rootstock-blue import findings-jsonl <file> --case <case>` |

See [family artifact bridges](design-docs/family-artifact-bridges.md) for the
schema ownership and compatibility rules.

## Evidence depth

Similar macOS concepts have different evidence depth in each component. For
example, the Core collector imports readable TCC grants, Red assesses access
preconditions without reading TCC database contents by default, and Blue parses
offline TCC artifacts into events and detections. A result from one component
must not be represented as evidence produced by another.

Stable cross-component technique identifiers are maintained in
[`references/technique-catalog.yaml`](references/technique-catalog.yaml).
Validate them with:

```bash
python3 scripts/check-technique-catalog.py
```

## Safety boundaries

- No component should export passwords, private keys, or token values.
- Red Lab mutation remains outside the default Red assessment executable.
- Blue is not a multi-platform EDR, SIEM, or MDM system.
- Family export is optional and never occurs implicitly.

Related entry points are the [Core README](../README.md),
[Red README](../rootstock-red/README.md), and
[Blue README](../rootstock-blue/README.md).
