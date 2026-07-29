# Case package v0 (`.rsbcase`)

Directory package (zip-friendly):

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

`schema_meta`, `sources`, `processes`, `file_events`, `timeline_events`, `findings`, `persistence_items`, `tcc_entries`, `custody_events`

## Events

`EventEnvelope` JSONL lines - see `RootstockBlueCore.EventEnvelope` and field taxonomy `Content/field-taxonomy/macos-esf.yaml`.

## CLI

```bash
rootstock-blue case create ./demo.rsbcase
rootstock-blue case verify ./demo.rsbcase
rootstock-blue query ./demo.rsbcase "SELECT value FROM schema_meta WHERE key='version';"
```
