# Investigate a Mac offline

Start with an existing collector scan. No Neo4j service is needed:

```sh
uv run --project graph --locked rootstock-graph-investigate scan.json \
  --format html --output reports/investigation.html
```

Open the HTML file locally. The review queue groups observations by priority,
with supporting records and a next review step. Search matches titles, rule IDs
and evidence text; filter by priority and expand a finding to inspect its facts.
The evidence graph is a linked relationship table, with source records below it.
The page includes no external scripts, fonts, analytics or network requests.

For reproducible automation, export JSON. To see durable changes, add an earlier
scan of the same Mac:

```sh
uv run --project graph --locked rootstock-graph-investigate scan.json \
  --baseline earlier-scan.json --format json --output reports/investigation.json
```

The report includes:

- Review findings for writable persistence, missing job programs, custom loader
  environments, non-loopback sockets, broad browser-extension permissions,
  custom certificate trust, unsigned applications, sensitive writable files,
  disabled protections and cached CVE matches.
- Baseline changes to application and program hashes, signing identities,
  extension permissions, TCC grants, persistence properties, receipts and host facts.
- Stable finding/evidence IDs, normalized source pointers, per-scan provenance,
  canonical content hashes, collection errors and explicit coverage limitations.
- Product-by-product CVE catalogue coverage, missing caches, fetch dates, stale or
  incomplete caches, match caps and unresolved NVD applicability conditions.

A review finding is not a malware verdict. A custom root or library setting may
be intentional. A non-loopback socket does not establish remote reachability.
PID/path relationships are associations from a non-atomic snapshot. Missing
records do not prove removal or successful remediation. When hardware UUIDs are
missing, same-host baseline matching falls back to hostname with a warning.
Processes and sockets are not used as durable baseline identities.

## CVE enrichment

Investigation only reads local caches. Fetching is a separate explicit action:

```sh
uv run --project graph --locked rootstock-graph-cve-enrichment \
  --fetch --scan-json scan.json
```

Then regenerate the report. A cached result with zero retained matches differs
from an app with no catalogue mapping or no cache. Neither establishes that the
software has no vulnerabilities. NVD CPE names come from a curated mapping;
incorrect product mappings can create incorrect results and require verification.
System applications are not individually matched by this workflow; matching the
macOS release does not cover every bundled component.

The graph workflow preserves fresh version evidence as `AFFECTED_BY`. Conditional,
stale, incomplete or legacy NVD evidence is retained as `HAS_CVE_CANDIDATE`, excluded
from CVE risk scoring, and visible in query 119. Query 120 shows coverage. Reimport
CVE evidence and rerun recommendations after refreshing or replacing a cache.

## Output and limitations

File outputs have mode `0600` and are written atomically. Keep them in the ignored
`reports/` directory: they contain confidential host metadata. Standard output
uses the terminal or shell redirection permissions instead.

JSON identifies its format as `rootstock-investigation/1`. It records the rule
version and the evidence actually used. Source hashes cover canonical parsed JSON
and normalized model JSON, not the original file bytes. Keep original scans and
cache snapshots separately if you need forensic custody or repeatable historical
feed state. The report does not reconstruct historical CVE state from a baseline.

The legacy collector format cannot prove complete collection of empty sources.
The report therefore shows empty evidence as unknown and retains collector errors.
This workflow supplements the full graph viewer and Blue case tooling.
