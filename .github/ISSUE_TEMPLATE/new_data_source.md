---
name: New Data Source
about: Propose a bounded macOS data source for the Rootstock Core collector
title: "[data-source] "
labels: data-source
---

## Data Source Name

Name the macOS subsystem or security boundary.

This template is for the Rootstock Core collector. Red and Blue use separate
artifacts and extension paths; describe any optional bridge impact below.

## What It Collects

- What security-relevant metadata would it extract?
- What macOS APIs or files does it read?
- Does it read metadata only, or could it expose secret values?

## Graph Model

- Node type, for example `ESF_Event`:
- Properties:
- Relationships to existing nodes:

## Elevation Requirements

- Works without elevation?
- Requires root?
- Requires Full Disk Access?

## Passive Collection Boundary

- Does it require network calls, telemetry, active probing, exploitation, or writes to the target system?
- If elevated access is needed but missing, what user-visible failure state should be emitted?

## macOS Version Support

- Minimum macOS version:
- Known version differences:

## Attack Paths Enabled

What new queries or attack paths would this data source enable?

## Contract Verification

- Collector models/schema change:
- Graph importer/model changes:
- Optional Red or Blue bridge impact, if any:
- Suggested fixture regression test:

## References

- Apple documentation links
- Research papers or blog posts
