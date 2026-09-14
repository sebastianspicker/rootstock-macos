# Rootstock interchange contracts

This directory contains the canonical contracts for artifacts exchanged
between Rootstock runtimes. Rootstock does not use one universal evidence
object. Each producer keeps its own wire format, owner, and compatibility rule.

| Contract | Canonical schema | Producer | Consumer | Compatibility rule |
| --- | --- | --- | --- | --- |
| [Collector scan](collector-scan/README.md) | `collector-scan/legacy-unversioned.schema.json` | `collector/Sources/Export/JSONExporter.swift` | graph and Blue scan import | The established wire format has no version field. Additive changes require a new versioned contract rather than silently changing this schema. |
| [Family open export](family-open-export/v1/README.md) | `family-open-export/v1/schema.json` | Red and Blue `FamilyOpenExporter` | `rootstock-graph-import-family-export` | `schema_version` is exactly `1`; producer and consumer must be changed together for a new version. |
| [CVE scan export](cve-scan-export/v7/README.md) | `cve-scan-export/v7/schema.json` | `modules/cve-scan/src/cve_scan/rootstock.py` | `rootstock-graph-import-cve-scan` | `schema_version` is exactly `7`; nodes retain typed extension properties. |
| [Red findings JSONL to Blue](red-findings-to-blue-jsonl/v1/README.md) | `red-findings-to-blue-jsonl/v1/` | Red `JSONLReporter` | Blue `FindingsJSONLImporter` | The producer record is strict; the retained consumer deliberately defaults missing fields and is therefore only object-shaped. |

`scripts/check-contracts.py` checks valid and invalid fixtures, JSON Schema
format constraints, and rules that span multiple records. Run it with the
graph package's locked environment:

```bash
uv run --project graph --locked python scripts/check-contracts.py
```
