# Frequently Asked Questions

## General

### What is Rootstock?
Rootstock is a graph-based attack path discovery tool for macOS. It collects security metadata
(TCC grants, entitlements, code signing, XPC services, etc.) and maps them into a Neo4j graph
to find privilege escalation paths.

### How is it different from BloodHound?
BloodHound focuses on Active Directory and Azure AD. Rootstock focuses on macOS-native security
boundaries (TCC, entitlements, code signing). They are complementary — see `docs/COMPARISON.md`.

### Is this a hacking tool?
Rootstock is a security assessment tool for authorized testing and research. It reads metadata
only and never modifies the system. See `docs/THREAT_MODEL.md` for details.

## Collector

### Why does the TCC scanner return 0 grants?
On macOS Tahoe (26.x) and Sequoia (15.x), even the user-level TCC.db requires Full Disk Access.
Grant FDA to your terminal app, then run: `sudo rootstock-collector --output scan.json`

### Why are some apps missing entitlements?
System apps on the Signed System Volume (SSV) may restrict `codesign` access. Unsigned apps
will also show no entitlements. These are logged as recoverable errors.

### Can I scan a remote Mac?
Not directly. Run the collector on the target Mac, transfer the JSON file, then import it
into Neo4j on your analysis workstation.

## Graph Pipeline

### Do I need Neo4j Enterprise?
No. Neo4j Community Edition (free, included in the Docker image) is sufficient.

### Can I import scans from multiple Macs?
Yes. Each import is tagged with a `scan_id`, and the importer preserves per-host
installations. Import multiple JSON files into the same Neo4j instance with
`graph/merge_scans.py` or repeated `graph/import.py` runs.

### Why do some queries return no results?
Queries that depend on TCC grant data (01, 02, 05, 07) require the collector to run
with Full Disk Access. Without FDA, TCC grants are not collected.
