# Rootstock documentation

[Investigate a Mac offline](INVESTIGATION.md): evidence-backed findings, baseline changes and CVE coverage.

Start with a component README for installation and commands. Use these guides
when you need to understand settings, evidence, or how the tools work together.

## Repository documentation

- [Architecture](ARCHITECTURE.md) describes implemented components,
  dependencies, runtime flows, state ownership, and extension rules.
- [Product family](FAMILY.md) lists supported artifact handoffs.
- [Configuration](CONFIGURATION.md) explains environment variables, input files, and
  local services.
- [Threat model](THREAT_MODEL.md) records security assumptions, sensitive data,
  and technical limitations.
- [Quality gates](QUALITY.md) documents the shared verifier.
- [Release procedure](RELEASING.md) covers preparing, checking, and publishing a Core alpha.
- [FAQ](FAQ.md) covers common collection and graph questions.
- [Frontend and reports](frontend.md) describes the static and live viewer.
- [Collector benchmarks](benchmarks/README.md) explains the measurement script
  and its private output files.
- [Screenshot capture](screenshots.md) explains how to reproduce the public
  synthetic viewer tour.
- [Interface design](../DESIGN.md) defines maintained viewer design rules.

## Component documentation

- [Collector](../collector/README.md)
- [Graph](../graph/README.md)
- [cve-scan](../modules/cve-scan/README.md)
- [Rootstock Red](../rootstock-red/README.md)
- [Rootstock Blue](../rootstock-blue/README.md)
- [RootstockMacFacts](../packages/RootstockMacFacts/README.md)
- [Interchange contracts](../contracts/README.md)

See [examples](../examples/README.md), the
[Neo4j Browser guide](guides/neo4j-browser-quickstart.md),
[design decisions](design-docs/index.md), and the shared
[technique catalog](references/technique-catalog.md),
[severity mapping](references/severity-mapping.md), and
[entitlement categories](references/entitlement-categories.md).
