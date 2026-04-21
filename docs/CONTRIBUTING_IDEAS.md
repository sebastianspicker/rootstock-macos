# Contribution Ideas

Areas where community contributions would be valuable.

## New Data Sources (Swift Collector)

- **Endpoint Security Framework (ESF)** — Real-time process events for live analysis
- **Login/Logout Hooks** — Legacy authentication hooks
- **Authorization Database** — `/etc/authorization` rules
- **Spotlight Metadata** — App metadata via `mdls`
- **Gatekeeper Assessment** — `spctl --assess` results per app
- **Network Extensions** — VPN, content filter, DNS proxy extensions
- **System Extensions** — Endpoint security, network, driver extensions

## New Cypher Queries

- Cross-host attack paths (when multi-host import is supported)
- MITRE ATT&CK mapping for discovered attack paths
- Compliance queries for CIS macOS benchmarks
- Time-based drift detection (compare scans over time)

## Visualization

- Web-based dashboard (alternative to Neo4j Browser)
- Attack path visualization with D3.js
- PDF report generation (in addition to Markdown)
- Integration with existing SIEM/SOAR platforms

## Testing & Quality

- Test on macOS 14, 15, 16 across different hardware
- Test with MDM-managed Macs (enterprise environments)
- Fuzzing the collector with malformed plist/SQLite inputs
- Performance optimization for Macs with 500+ apps

## Documentation

- Video walkthrough of a full scan-to-attack-path workflow
- Blog posts explaining specific attack paths found
- Translation of documentation to other languages
- Integration guides for pentest workflows
