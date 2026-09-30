# Security policy

## Reporting a vulnerability

Do not open public GitHub issues for security vulnerabilities. Use
[GitHub private vulnerability reporting](https://github.com/sebastianspicker/rootstock-macos/security/advisories/new)
to submit reports confidentially.

Include:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix, if any


## Supported versions

| Version | Supported |
|---------|-----------|
| `main` branch | Yes |
| Pre-release tags | Best effort |
| Other branches | No |

Alpha tags are pre-release. Prefer building from a reviewed commit or verifying
published archive checksums. Schemas and packaging may still change.

## Scope

Use the same private reporting channel for Core, cve-scan, Red, Blue, and
RootstockMacFacts. Name the affected component and file format or command.
Reports may cover:

- Vulnerabilities in the Swift collector or Python graph pipeline
- Credential leakage or unintended secret exposure
- Supply chain risks in dependencies, GitHub Actions, or build artifacts
- Authorization, safety-boundary, or unintended-network-access defects in
  Red or Blue components

The following are out of scope:

- Security findings discovered by Rootstock
- Issues requiring physical access to the machine running the collector
- Social engineering attacks against project maintainers

## Security assumptions

- The Swift collector is read-only and local. It does not upload scans,
  collect telemetry, or perform exploitation.
- Treat real `scan.json`, graph exports, viewer files, reports, Neo4j
  volumes, screenshots, package inventories, and CVE scan outputs as
  confidential local data.
- The bundled Neo4j Compose file binds Browser and Bolt to `127.0.0.1` and
  requires `NEO4J_AUTH`; do not expose it remotely without an explicit access
  control layer.
- The FastAPI viewer API requires `ROOTSTOCK_API_TOKEN` for `/api/*` routes.
- The token must be at least 32 bytes; generate it from a cryptographically
  secure random source. API responses disable caching and embedding in frames, and restrict
  where browser resources can load from.
- The alpha API and its Neo4j connection are both loopback-only. The server
  reads `NEO4J_PASSWORD` from the environment and does not accept it on the
  command line. Non-loopback binds are refused and there is no remote-mode
  override.
- CVE enrichment uses cached/static data by default. Outbound refreshes are
  opt-in via `graph/pipeline.sh --refresh-cve` or
  `rootstock-graph-cve-enrichment --fetch` in the locked graph environment.
- Rootstock Red and Rootstock Blue have separate executables, artifacts, and
  component policies. Their optional family bridges are explicit and are not
  enabled by default.
- cve-scan scope files are trusted executable configuration: credential entries
  can select commands used for local WinRM helpers or remote SSH collection.
  Do not run scope files from unreviewed pull requests or downloads.
- `ROOTSTOCK_BLUE_ULS_BINARY` selects an external executable that runs with the
  Blue process identity. Use only a locally verified binary that other users cannot replace from the intended upstream project.
- Red Lab consent flags record an acknowledgement. They do not authenticate
  the operator or prove that someone else authorized the work.
- Except where a component explicitly enforces owner-only output, local file
  confidentiality depends on the parent directory and process umask. Use
  private directories for all real evidence.

## Research conduct

Security research reports should:

- Make a good-faith effort to avoid privacy violations, data destruction, and
  service disruption
- Report vulnerabilities through the channels described above
- Allow reasonable time for remediation before public disclosure
