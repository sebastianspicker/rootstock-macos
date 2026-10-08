# DD-014: Offline investigation and explicit CVE uncertainty

Status: Implemented; review pending
Date: 2026-10-08

## Context

A researcher should be able to inspect a collected Mac without provisioning a
database. Inventory alone does not explain which observations deserve review,
which source records support them, or how they differ from an earlier scan.
The legacy collector format also cannot prove that an empty collection was
successfully collected.

DD-012's product/version filter flattened NVD configurations. It could discard
required conditions, accepted offline cache data without showing freshness,
and used the same graph edge for registry and NVD evidence. This conflated a
candidate with sufficient product/version evidence for prioritization.

## Decision

`rootstock-graph-investigate` consumes a bounded, validated collector JSON file
and existing local CVE caches. It does not connect to Neo4j, fetch feeds, launch
collectors or probe services. Output is text, JSON (`rootstock-investigation/1`),
or a self-contained searchable HTML report. File outputs are atomically written
with owner-only permissions. Scan records, facts, relationships, review rules,
and limitations remain available in the JSON output.

Evidence has stable identifiers, a normalized scan JSON pointer, a scan ID and
source kind. The output records SHA-256 digests of canonical parsed source JSON
and normalized model JSON. These are content fingerprints, not raw-file custody
hashes or signatures. Duplicate app installations remain path-distinct. Exact
executable paths and same-scan PIDs establish associations; they do not establish
process-launch attribution or atomic observation. No modeled attack paths are
needed to produce the report.

Baseline comparisons require matching hardware UUIDs when both exist. Otherwise,
equal hostnames permit comparison with an explicit identity warning. The baseline
must not be newer than the current scan. Durable application, persistence,
extension, trust, receipt, TCC, ACL and host facts are compared. Processes and
sockets are excluded from durable comparison because PID identity is unstable.
Missing records are called **no longer observed**, never resolved. Historical CVE
state is not reconstructed from today's cache.

NVD conditions retain AND/OR structure and nesting. Required conditions that
cannot be established from the selected CPE remain conditional; negation is not
silently discarded. CPE part must agree, rejected CVEs are excluded, and
edition/update/architecture qualifiers remain conditions to verify. This is a
conservative candidate matcher, not a complete CPE applicability engine.

Cache entries carry parser revision, fetch time, pagination completeness and
retained-match limits. Old parser revisions refresh on the next explicit fetch.
They remain available offline as unverified candidates. Missing or stale KEV
catalogues do not establish a negative KEV membership result.

Fresh, complete, current-parser NVD version matches use `AFFECTED_BY` with
`match_source: 'nvd'`; unresolved, stale, incomplete and legacy matches use
`HAS_CVE_CANDIDATE`. Candidate edges are non-traversable in OpenGraph and are
excluded from existing CVE risk scoring and update recommendations. Match caps
limit coverage, not the validity of individual retained matches. Registry edges
retain their own `match_source: 'registry'`. Multiple CPE aliases preserve their
individual criteria. Queries 119 and 120 expose candidates and product coverage.
NVD update recommendations are rebuilt with per-scan, per-installation keys.

## Architecture and compatibility

The new `investigation` package depends on foundation, vulnerability and ingestion
helpers; no existing lower layer imports it. It is parallel to graph reporting.
The collector scan contract stays compatible. JSON consumers must check the
investigation `schema_version`; this is an alpha report format, not a replacement
for the existing cross-product interchange contracts.

This supersedes DD-012's assumption that every retained cached CPE match belongs
on `AFFECTED_BY`. Reimport the scan's CVE cache to rebuild NVD edge classification,
then rerun scoring/recommendations. Use an explicit cache refresh to replace
legacy parser evidence. Existing shared LaunchItem/XPC graph identities and
other multi-host limitations from DD-013 remain outside this decision; the
offline report operates on a single validated host snapshot.
