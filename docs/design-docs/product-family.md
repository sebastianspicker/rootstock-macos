# DD-010: Product Family Architecture

Status: Accepted
Date: 2026-07-16

## Context

The monorepo hosts three product trees that share macOS security domains
(TCC, persistence, MDM, codesign, keychain metadata, sudoers, and related
surfaces) but use different contracts, audiences, and honesty models:

| Product | Role | Primary artifact |
|---------|------|------------------|
| Core Rootstock (`collector/` + `graph/` + `modules/cve-scan/`) | Passive attack-path graph workstation | `scan.json` → Neo4j |
| `rootstock-red/` | Assess-first authorized red/purple findings | `Finding` JSONL/SARIF/MD |
| `rootstock-blue/` | Post-incident DFIR case platform | `.rsbcase` + `EventEnvelope` |

Without an explicit family decision, operators and implementers treat the trees
as either one product or unrelated forks, and domain logic drifts three ways.

## Decision

1. Products remain separate pipelines. Do not merge red, blue, and collector
   into a single binary, schema, or runtime.
2. Coherence is achieved via:
   - Family documentation (`docs/FAMILY.md`)
   - Shared neutral vocabulary and probe utilities (paths, TCC service
     names, launchd discovery helpers) - not product serializers
   - A cross-product technique catalog with stable family IDs
   - Optional, versioned artifact bridges (same pattern as
     [DD-009 cve-scan Artifact Bridge](cve-scan-artifact-bridge.md))
3. Root documentation describes the core attack-path spine in full and
   links sibling products as related monorepo products without claiming a
   unified public surface unless release policy expands that intentionally.

### Guardrails (do not collapse)

| Boundary | Reason |
|----------|--------|
| Neo4j multi-hop path math stays in `graph/` | Requires stable entity IDs and edge vocabulary from `ScanResult` |
| Red non-prompting TCC default | Assess OPSEC; no TCC.db row dump by default |
| Lab mutate only in `rootstock-red-lab` | Assess binary must stay fail-closed for mutation |
| Blue case custody (`.rsbcase`) | DFIR evidence package ≠ graph snapshot ≠ findings dump |
| No secret extraction | Architectural invariant across the family (DD-004) |
| cve-scan imports only `rootstock-export.json` | Keeps scanner and Neo4j decoupled |

## Rationale

Domain duplication is real, but depth and safety models differ: collector
parses when readable for graph inventory; red optimizes for authorized assess
without interactive input; blue optimizes for offline evidence trees and super-timeline
custody. Forcing one model destroys product value. Sharing path constants,
service registries, and optional JSON bridges reduces drift without erasing
intent.

## Alternatives Considered

- One mega-binary / one schema: Rejected - incompatible safety rails and
  output models.
- Docs-only forever: Rejected - path and TCC name drift will continue.

## Consequences

- Implementers add monorepo links in `README.md`, `ARCHITECTURE.md`, and product
  READMEs.
- Shared Swift code lives in neutral packages (for example
  `packages/RootstockMacFacts`) with no dependency on `ScanResult`,
  `Finding`, or `EventEnvelope`.
- Cross-product handoffs use versioned JSON artifacts, not SPM imports of
  another product’s core types.
- Technique IDs in `docs/references/technique-catalog.yaml` map graph queries,
  red findings, and blue detections without requiring runtime coupling.

## See also

- [Product family map](../FAMILY.md)
- [DD-009: cve-scan Artifact Bridge](cve-scan-artifact-bridge.md)
- [Family artifact bridges](family-artifact-bridges.md)
