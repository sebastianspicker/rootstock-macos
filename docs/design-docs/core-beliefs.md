# Core Design Principles

These principles document current architectural constraints and review
criteria.

## 1. Collect metadata, not secret values

Rootstock discovers relationships between security boundaries - not the secrets they
protect. We read ACLs, not passwords. We read entitlements, not tokens. This is not just
policy; it's an architectural invariant enforced at the data model level.

Test: Changing a Keychain secret value without changing item or ACL metadata
does not change Rootstock's output.

## 2. Preserve partial evidence on recoverable failures

The collector runs with different permissions and host configurations. A
recoverable module error is recorded in the scan while other selected modules
continue. Non-recoverable errors remain visible as failed scan status.

Test: Running without elevation or Full Disk Access still writes a parseable
artifact that records unavailable evidence and collection errors.

## 3. Use replayable artifacts between collection and analysis

The collector writes JSON that can be stored, diffed, and replayed through the
analysis pipeline. The collection itself observes live host state and is not
reproducible unless the relevant host evidence is unchanged.

## 4. Pair modeled paths with defensive context

Modeled paths should identify their assumptions and relevant defensive review
steps. A graph relationship is not evidence that exploitation occurred.

## 5. Isolate operating-system-specific behavior

macOS security mechanisms evolve significantly with each annual release. The architecture
must isolate version-specific logic behind narrow interfaces. Paths, service
names, and database schemas require fixture and compatibility review.

## 6. Treat graph contracts as the primary integration surface

The collector feeds the graph model, relationships, and queries. When
prioritizing work, ask: "Does this make the graph more
accurate or more queryable?"
