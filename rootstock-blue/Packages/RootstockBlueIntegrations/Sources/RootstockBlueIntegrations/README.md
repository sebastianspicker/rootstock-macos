# RootstockBlueIntegrations

Rootstock Blue integrates with external tools through small adapters. Keep
those tools separate and use their documented interfaces.

| Integration | Blue behavior |
|---|---|
| [Santa](../../../../docs/integrate/santa.md) | Parse supported decision-log fields into timeline events and produce manual rule suggestions |
| Velociraptor / UAC | Parse an already-extracted collection tree with the offline parsers |
| [Mandiant macos-UnifiedLogs](../../../../Tools/sidecars/macos-unifiedlogs/README.md) | Run a separately installed parser selected through `ROOTSTOCK_BLUE_ULS_BINARY` |
| [Fleet / osquery](../../../../docs/integrate/fleet-osquery.md) | Convert event envelopes to osquery-shaped rows or export a case timeline as JSONL |

Do not vendor AGPL server code into a privileged process without a license
review. An external executable runs with the same identity and access as Blue,
so review its source and verify the ownership and integrity of its path before
configuring it.
