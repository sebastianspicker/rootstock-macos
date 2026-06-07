---
name: New Data Source
about: Propose a new macOS data source for the collector
title: "[data-source] "
labels: data-source
---

## Data Source
Name of the macOS subsystem or security boundary.

Scope note: analysis and remediation should target active source/docs, not
`deprecated/`, `docs/archive/`, or `docs/deprecated/`.

## What It Collects
- What security-relevant metadata would this extract?
- What macOS APIs or files does it read?
- Does it read metadata only, or could it expose secret values?

## Graph Model
- Node type: (e.g., `ESF_Event`)
- Properties:
- Relationships to existing nodes:

## Elevation Requirements
- Works without elevation?
- Requires root?
- Requires Full Disk Access?

## Passive Collection Boundary
- Does this require network calls, telemetry, active probing, exploitation, or
  writes to the target system?
- If any elevated access is needed, what user-visible failure state should be
  emitted when access is missing?

## macOS Version Support
- Minimum macOS version:
- Known version differences:

## Attack Paths Enabled
What new queries or attack paths would this data source enable?

## Contract and Verification
- Collector models/schema that would change:
- Graph importer/model changes:
- Suggested fixture or regression test:

## References
- Apple documentation links
- Research papers or blog posts
