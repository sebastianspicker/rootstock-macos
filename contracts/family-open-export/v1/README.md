# Family open export v1

The family open export is an optional, allowlisted graph artifact emitted by
`rootstock-red/Sources/MacReportKit/FamilyOpenExporter.swift` and
`rootstock-blue/Sources/RootstockBlueInterchange/FamilyOpenExporter.swift`.
Import it with `rootstock-graph-import-family-export`.

This artifact is separate from the collector's `scan.json`. Version 1 permits
only the Host, Finding, LaunchItem, and Protection labels and their three
declared edge types. The schema describes everything accepted by the importer,
rather than only the records currently emitted by Red and Blue:
`node_types` and `edge_vocabulary` may be non-empty allowlisted subsets,
`edge_types` is optional, node and edge extension keys are retained, and no
product-specific node field is required.

## Stable producer IDs

Current version 1 producers derive every node ID as
`<NodeType>:<readable-prefix>--<sha256>`. `readable-prefix` is the first 80
ASCII letters, digits, dots, underscores, or hyphens from the canonical raw
key, with every other character replaced by an underscore. `sha256` is the
lowercase SHA-256 hex digest of that complete UTF-8 raw key. The digest is authoritative:
the readable prefix is only a convenience for people reading the export. This
keeps `a/b` and `a?b` distinct even though they produce the same prefix.

Depending on the node type, the canonical raw key is the effective host name,
lowercased protection name, finding ID, or the launch label, path, and program
joined by unit separators. Blue uses a persisted event UUID only when every
launch identity field is absent. It never creates a new UUID during export.
This identifier rule applies to version 1 producers and does not change the
schema.

The importer also enforces declared node labels, requires `edge_types` to be a
subset of `edge_vocabulary`, rejects duplicate node IDs, and requires every
edge endpoint to exist in the document. Those cross-record rules are checked by
`scripts/check-contracts.py` through the importer itself. Separate parity tests
check the complete vocabularies and node shapes emitted by the current Red and
Blue exporters without narrowing version 1 interoperability.
