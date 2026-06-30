# Frequently Asked Questions

## General

### What is Rootstock?

Rootstock is a graph-based macOS attack-path discovery tool. It collects
security metadata such as TCC grants, entitlements, code signing, XPC services,
and persistence items, then maps them into Neo4j to find privilege escalation
paths.

### How is Rootstock different from BloodHound?

BloodHound focuses on Active Directory and Azure AD. Rootstock focuses on
macOS-native security boundaries such as TCC, entitlements, and code signing.
They are complementary. See [COMPARISON.md](COMPARISON.md).

### Is this a hacking tool?

Rootstock is for authorized security assessment and research. The collector
reads local metadata and does not modify the system. See
[THREAT_MODEL.md](THREAT_MODEL.md).

## Collector

### Why does the TCC scanner return 0 grants?

On macOS Sequoia 15 and Tahoe 26, even user-level `TCC.db` reads can require
Full Disk Access. Grant FDA to the terminal app, then run the built collector
with the needed privileges:

```bash
sudo collector/.build/release/RootstockCLI --output scan.json
```

### Why are some apps missing entitlements?

System apps on the Signed System Volume may restrict `codesign` access. Unsigned
apps can also have no entitlements. Rootstock records these as recoverable
module errors instead of failing the whole scan.

### Can I scan a remote Mac?

Not directly. Run the collector on the target Mac, transfer the JSON file, and
import it into Neo4j on the analysis workstation.

## cve-scan Module

### What is `modules/cve-scan/`?

It is Rootstock's scoped CVE evidence module. It collects package, service, TLS,
web, container, and configuration evidence from an explicit scope file, then
writes local reports plus `rootstock-export.json` for graph import.

### Does Rootstock run cve-scan automatically?

No. Run cve-scan separately, then import the prebuilt artifact:

```bash
python3 graph/import_cve_scan.py --input <rootstock-export.json>
NEO4J_PASSWORD=CHANGE_ME bash graph/pipeline.sh <scan.json> --cve-scan-export <rootstock-export.json>
```

### Can I commit cve-scan outputs?

No. Real `scan.json`, `rootstock-export.json`, reports, caches, generated
viewers, screenshots, package inventories, and CVE scan outputs can contain
infrastructure data. Keep them local. The checked-in
`examples/cve-scan-export.json` file is synthetic.

### Can I commit archived plans, audits, or status files?

No. Retired planning, audit, status, deprecated-note, generated-report,
investigation, announcement, and remediation material is not part public
documentation set. Keep local copies in ignored private or archive paths.

## Graph Pipeline

### Do I need Neo4j Enterprise?

No. Neo4j Community Edition is sufficient, including the Docker image used by
`graph/docker-compose.yml`.

### Can I import scans from multiple Macs?

Yes. Each import is tagged with `scan_id`, and the importer preserves per-host
installations. Import multiple JSON files into the same Neo4j instance with
`graph/merge_scans.py` or repeated `graph/import_scan.py` runs.

### Why do some queries return no results?

Queries that depend on TCC grant data, especially queries 01, 02, 05, and 07,
require collector output from a run with Full Disk Access. Without FDA, TCC
grants are not collected.
