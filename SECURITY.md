# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `dev` branch | Yes |
| `main` branch | Yes |
| All other branches | No |

## Scope

Rootstock is a macOS security boundary analysis tool. The following reports are
in scope:

- Vulnerabilities in the Swift collector or Python graph pipeline
- Credential leakage or unintended secret exposure
- Supply chain risks in dependencies, GitHub Actions, or build artifacts
- Issues that could let the tool be weaponized beyond its intended purpose

The following are out of scope:

- Security findings discovered by Rootstock
- Issues requiring physical access to the machine running the collector
- Social engineering attacks against project maintainers

## Operational Boundaries

- The Swift collector is passive and local-only. It must not upload scans,
  collect telemetry, or perform active exploitation unless a maintainer
  explicitly requests and scopes a test.
- Treat real `scan.json`, graph exports, generated viewers, reports, Neo4j
  volumes, screenshots, package inventories, and CVE scan outputs as
  confidential local data.
- The bundled Neo4j Compose file binds Browser and Bolt to `127.0.0.1` and
  requires `NEO4J_AUTH`; do not expose it remotely without an explicit access
  control layer.
- The FastAPI viewer API requires `ROOTSTOCK_API_TOKEN` for `/api/*` routes.
  Bind it to loopback unless remote exposure is explicitly intended and started
  with `--allow-remote`.
- CVE enrichment uses cached/static data by default. Outbound refreshes are
  opt-in via `graph/pipeline.sh --refresh-cve` or
  `graph/cve_enrichment.py --fetch`.

## Reporting a Vulnerability

Do not open public GitHub issues for security vulnerabilities. Use
[GitHub private vulnerability reporting](https://github.com/sebastianspicker/rootstock/security/advisories/new)
to submit reports confidentially.

Include:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix, if any

## Response Expectations

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 7 days
- **Resolution target:** within 30 days for confirmed vulnerabilities

## Safe Harbor

Good-faith security research is authorized. We will not pursue legal action
against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption
- Report vulnerabilities through the channels described above
- Allow reasonable time for remediation before public disclosure
