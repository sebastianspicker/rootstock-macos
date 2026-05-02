# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `dev` branch | Yes |
| `main` branch | Yes |
| All other branches | No |

## Scope

Rootstock is a macOS security boundary analysis tool. The following are in scope
for security reports:

- Vulnerabilities in the Swift collector or Python graph pipeline
- Credential leakage or unintended secret exposure
- Supply chain risks (compromised dependencies, Actions, build artifacts)
- Issues that could allow the tool to be weaponized beyond its intended purpose

## Operational Boundaries

- The Swift collector is passive and local-only. It must not upload scans,
  collect telemetry, or perform active exploitation.
- Treat real `scan.json`, graph exports, generated viewers, reports, Neo4j
  volumes, and screenshots as confidential local data.
- The bundled Neo4j Compose file binds Browser and Bolt to `127.0.0.1` and
  requires `NEO4J_AUTH`; do not expose it remotely without an explicit access
  control layer.
- The FastAPI viewer API requires `ROOTSTOCK_API_TOKEN` for every `/api/*`
  route. Bind it to loopback unless remote exposure is explicitly intended and
  started with `--allow-remote`.
- CVE enrichment uses cached/static data by default. Outbound CVE refreshes are
  opt-in via `graph/pipeline.sh --refresh-cve` or `graph/cve_enrichment.py --fetch`.

The following are **out of scope**:

- Security findings *discovered by* Rootstock (these are expected output)
- Issues requiring physical access to the machine running the collector
- Social engineering attacks against project maintainers

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub's private vulnerability reporting](https://github.com/sebastianspicker/rootstock/security/advisories/new)
to submit your report confidentially.

Include:
1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

## Response Expectations

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Resolution target:** Within 30 days for confirmed vulnerabilities

## Safe Harbor

We consider security research conducted in good faith to be authorized. We will
not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption
- Report vulnerabilities through the channels described above
- Allow reasonable time for remediation before public disclosure
