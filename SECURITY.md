# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch | Yes |
| Pre-release tags | Best effort |
| Other branches | No |

Alpha tags are pre-release. Prefer building from a reviewed commit or verifying
published archive checksums. Schemas and packaging may still change.

## Scope

This policy covers security defects in the root-level Rootstock Core collector,
graph pipeline, viewer, and optional cve-scan bridge. Reports involving
Rootstock Red, Rootstock Blue, or the shared RootstockMacFacts package use the
same private channel; identify the affected component and artifact. The
following reports are in scope:

- Vulnerabilities in the Swift collector or Python graph pipeline
- Credential leakage or unintended secret exposure
- Supply chain risks in dependencies, GitHub Actions, or build artifacts
- Authorization, safety-boundary, or unintended-network-access defects in
  Red or Blue components

The following are out of scope:

- Security findings discovered by Rootstock
- Issues requiring physical access to the machine running the collector
- Social engineering attacks against project maintainers

## Operational Boundaries

- The Swift collector is passive and local-only. It must not upload scans,
  collect telemetry, or perform active exploitation unless a maintainer
  explicitly requests and scopes a test.
- Treat real `scan.json`, graph exports, viewer files, reports, Neo4j
  volumes, screenshots, package inventories, and CVE scan outputs as
  confidential local data.
- The bundled Neo4j Compose file binds Browser and Bolt to `127.0.0.1` and
  requires `NEO4J_AUTH`; do not expose it remotely without an explicit access
  control layer.
- The FastAPI viewer API requires `ROOTSTOCK_API_TOKEN` for `/api/*` routes.
- The token must be at least 32 bytes; generate it from a cryptographically
  secure random source. API responses disable caching and framing and restrict
  browser resource origins.
- The alpha API and its Neo4j connection are both loopback-only. The server
  reads `NEO4J_PASSWORD` from the environment and does not accept it on the
  command line. Non-loopback binds are refused and there is no remote-mode
  override.
- CVE enrichment uses cached/static data by default. Outbound refreshes are
  opt-in via `graph/pipeline.sh --refresh-cve` or
  `graph/cve_enrichment.py --fetch`.
- Rootstock Red and Rootstock Blue have separate executables, artifacts, and
  component policies. Their optional family bridges are explicit and are not
  enabled by default.

## Reporting a Vulnerability

Do not open public GitHub issues for security vulnerabilities. Use
[GitHub private vulnerability reporting](https://github.com/sebastianspicker/rootstock/security/advisories/new)
to submit reports confidentially.

Include:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix, if any

## Good-Faith Research

Security research reports should:

- Make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption
- Report vulnerabilities through the channels described above
- Allow reasonable time for remediation before public disclosure
