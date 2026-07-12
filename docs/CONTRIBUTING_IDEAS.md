# Contribution Ideas

Areas where community contributions would be valuable.

## New Data Sources (Swift Collector)

- **Endpoint Security Framework event snapshots** — Bounded, passive coverage
  data that complements the existing ESF monitoring-gap inference.
- **Login/logout hook enrichment** — Legacy authentication hooks and launch
  paths not already covered by persistence data.
- **Spotlight metadata enrichment** — App metadata via `mdls` for better app
  identity and provenance.
- **Network extension detail enrichment** — Deeper VPN, content-filter, and DNS
  proxy context on top of the existing system-extension module.
- **Per-app Gatekeeper context** — More explicit notarization and quarantine
  evidence beyond current code-signing and quarantine fields.

## New Cypher Queries

- Cross-host attack paths (when multi-host import is supported)
- MITRE ATT&CK mapping for discovered attack paths
- Compliance queries for CIS macOS benchmarks
- Time-based drift detection (compare scans over time)

## Visualization

- Additional keyboard and VoiceOver usability testing with large real-world
  graph shapes represented by synthetic fixtures
- Saved-query organization and result export improvements that preserve the
  current local, framework-free viewer
- First-class PDF export built on the existing semantic print report
- Integration with existing SIEM/SOAR platforms

## Testing & Quality

- Test on macOS 14, 15, and 26 across different hardware
- Test with MDM-managed Macs (enterprise environments)
- Fuzzing the collector with malformed plist/SQLite inputs
- Performance optimization for Macs with 500+ apps

## Documentation

- Video walkthrough of a full scan-to-attack-path workflow
- Blog posts explaining specific attack paths found
- Translation of documentation to other languages
- Integration guides for pentest workflows
