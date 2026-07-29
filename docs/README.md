# Rootstock documentation

This directory contains the maintained public documentation for the Core,
Rootstock Red, and Rootstock Blue source trees.

## Start here

- [Product family](FAMILY.md) describes component boundaries, artifacts, and
  explicit interoperability commands.
- [Architecture](../ARCHITECTURE.md) describes runtime boundaries, contracts,
  and data flow.
- [Threat model](THREAT_MODEL.md) describes data sensitivity, network access,
  mutation boundaries, and operator assumptions.
- [Quality gates](QUALITY.md) lists the checks used for the alpha candidate.
- [Release procedure](RELEASING.md) records the approval-only publication
  sequence. It does not authorize a release.
- [FAQ](FAQ.md) covers common setup and interpretation questions.
- [Frontend and reports](frontend.md) describes the maintained viewer and
  report interfaces.
- [Technical comparison](COMPARISON.md) defines the repository's scope relative
  to adjacent tools without claiming feature parity.

## Detailed material

- [Guides](guides/) contain operator and module instructions.
- [Design documents](design-docs/) explain implemented architectural
  decisions. Source and tests define current behavior.
- [References](references/) contain the technique catalog, severity mapping,
  and macOS security reference material.
- [Research notes](research/) provide background for selected implemented
  behavior. They are not compatibility guarantees.
- [Benchmarks](benchmarks/) define public methods and acceptance thresholds.
  Machine-specific results remain local.
- [Screenshots](screenshots/) contains four Playwright captures of the
  maintained viewer using synthetic data.
- [Interface design](../DESIGN.md) records viewer and report presentation rules.

## Documentation policy

Only indexed, maintained documents are part of the public documentation set.
Private data and reproducible local output belong in ignored paths. Statements
about current behavior must remain supported by source or tests.
