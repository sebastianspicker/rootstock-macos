# Case package v0 (`.rsbcase`)

A `.rsbcase` is a directory with this layout:

```text
Case.rsbcase/
  manifest.json
  custody.jsonl
  case.sqlite
  events/es/*.jsonl
  events/net/*.jsonl
  artifacts/
  logarchives/
  plugins/
  sha256sums.txt
```

## SQLite tables (v0)

The SQLite database contains these tables:

`schema_meta`, `sources`, `processes`, `file_events`, `timeline_events`,
`findings`, `persistence_items`, `tcc_entries`, and `custody_events`.

## Events

Event streams contain one `RootstockBlueCore.EventEnvelope` JSON object per
line. Field names are defined in
[`Content/field-taxonomy/macos-events.yaml`](../Content/field-taxonomy/macos-events.yaml).

## Integrity

`sha256sums.txt` inventories every regular file that carries evidence, except
the inventory itself. `case verify` rejects missing or unexpected entries,
checksum mismatches, malformed custody or event JSONL, symbolic links,
unfinished write journals, duplicate event IDs, and differences between an
event's JSONL record and its SQLite timeline row.

Event and custody writes keep a journal until their JSONL, SQLite, and checksum
updates are complete. If a write is interrupted, later verification fails and
calls attention to the incomplete update. Format v0 does not claim that these
updates are atomic or durable across power loss because it does not enforce
ordered synchronization of every file and directory.

One logical event batch uses one case write journal and can include one custody
note. Verification reads event and custody JSONL incrementally and checks each
event through a prepared SQLite lookup. It finds duplicates with a
connection-local, file-backed SQLite temporary table whose page cache is
bounded. Verification stops if it cannot create that storage.

The checksum inventory establishes consistency within the package. It cannot
authenticate the original evidence or identify its collector. Create cases in
a private directory you control; files in the package can inherit permissions
from the process umask and parent directory.

Older cases that predate full-inventory verification need a new hash inventory
made from a trusted local copy. Blue has no automatic reseal or migration
command, and the public case API does not expose a checksum rewrite for legacy
packages.

## CLI

```bash
rootstock-blue case create ./demo.rsbcase
rootstock-blue case verify ./demo.rsbcase
rootstock-blue query ./demo.rsbcase "SELECT value FROM schema_meta WHERE key='version';"
```

The query command accepts only `SELECT` statements. Use the case APIs for any
write so the JSONL, SQLite, custody, journal, and checksum records stay in sync.
