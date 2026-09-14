---
name: New data source
about: Propose a macOS data source for the Core collector
title: "[data-source] "
labels: data-source
---

## Data source

Name the macOS subsystem and explain the security question this evidence
would help answer. This template covers the Core collector; use a feature
request for Red or Blue extensions.

## Evidence to collect

- APIs or files to read:
- Metadata to retain:
- Secret values or personal data that must be excluded:

## Graph representation

- Node type, such as `Application`:
- Properties:
- Relationships to existing nodes:
- Example query the new evidence would support:

## Permissions and platform support

- Minimum macOS version and known version differences:
- Required privileges and Full Disk Access:
- Result to report when access is unavailable:

The Core collector is read-only and local. Explain any proposed network
request or host write so its effect can be reviewed.

## Compatibility and tests

Describe changes needed in the collector schema, graph importer, and any Blue
scan import. Suggest synthetic fixtures for success, missing access, and
unsupported data.

## References

Link relevant Apple documentation or research.
