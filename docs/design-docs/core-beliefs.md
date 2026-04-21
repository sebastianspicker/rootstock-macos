# Core Beliefs — Design Principles

> These principles guide every decision in Rootstock.
> When in doubt, refer back to these.

## 1. Metadata, Never Secrets

Rootstock discovers *relationships* between security boundaries — not the secrets they
protect. We read ACLs, not passwords. We read entitlements, not tokens. This is not just
policy; it's an architectural invariant enforced at the data model level.

**Test:** If you removed all Keychain passwords from the system, Rootstock's output would
be identical.

## 2. Graceful Degradation Over Hard Failure

The collector runs in diverse environments — some with FDA, some without; some with SIP
disabled, most with it enabled. Every data source module must produce partial results
rather than failing the entire scan.

**Test:** Running the collector as a normal user (no elevation, no FDA) should still
produce a useful graph — just with fewer nodes.

## 3. Static Artifacts Over Live State

Rootstock produces JSON files that can be stored, diffed, shared, and replayed. The
collector doesn't maintain persistent state or require a running service. This makes
results reproducible and auditable — critical for both red team reports and academic papers.

## 4. Offense Informs Defense

Every attack path Rootstock discovers should have an actionable defensive recommendation.
The graph model is designed for both red teams ("how do I get to FDA?") and blue teams
("which apps with FDA are injectable?").

## 5. Apple Changes Things

macOS security mechanisms evolve significantly with each annual release. The architecture
must isolate version-specific logic behind stable interfaces. Hard-coded paths, service
names, and database schemas are technical debt with a one-year half-life.

## 6. The Graph Is the Product

The collector is a means to an end. The real value is in the graph model, the relationships,
and the queries. When prioritizing work, always ask: "Does this make the graph more
accurate or more queryable?"
