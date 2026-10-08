# DD-013: Identify launch items and XPC services by plist

Status: Accepted
Date: 2026-10-08

## Context

`LaunchItem` and `XPC_Service` nodes were merged on their launchd `label`. The
label is chosen by the plist author, so two plists can share it: an app's
embedded LaunchAgent and a copy in `~/Library/LaunchAgents`, a daemon and a
stale leftover, or a malicious plist that reuses a trusted label. Merging on the
label collapsed them into one node and let the properties of the last import
win, which hid exactly the duplicate that deserved attention.

## Decision

A `LaunchItem` is keyed by `item_key = "<type>:<path>:<label>"` and an
`XPC_Service` by its plist `path`: one plist is one job. `label` stays an
indexed property on both. `NODE_KEY_PROPERTY`, `setup_schema`, the importers,
`mark_owned`, the OpenGraph export and every packaged query that matched on
`{label: …}` use the new keys.

## Rationale

The plist path is what launchd loads and what an attacker writes; it is stable
across scans of the same host and unique on disk. Including the type and label
in `item_key` keeps login items, cron jobs and login hooks, which share
preference files, distinct.

## Alternatives Considered

- Keeping the label and adding the path as a property: rejected because the
  merge would still collapse two plists into one node.
- Keying on a content hash of the plist: rejected because the node would change
  identity whenever the plist is edited, which breaks history and owned marks.

## Consequences

Queries that look a job up by label can return several nodes and must say which
one they mean (the packaged queries return the plist path alongside the label).

Migration: `rootstock-graph-setup-schema` drops the obsolete
`launch_label_unique` and `xpc_label_unique` constraints and creates
`launch_item_key_unique` and `xpc_path_unique`. Launch item and XPC service
nodes are shared across scans, so nodes imported under the old label key stay in
an existing database next to the new ones. Import into a fresh database after
running setup-schema, or delete the old nodes first (`MATCH (l:LaunchItem)
WHERE l.item_key IS NULL DETACH DELETE l`, and the same for `XPC_Service`
nodes without a `path`).
