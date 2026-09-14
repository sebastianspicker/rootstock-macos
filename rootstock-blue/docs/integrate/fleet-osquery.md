# Fleet and osquery

`RootstockBlueIntegrations.OsqueryExport` maps an event envelope to a flat
string dictionary suitable for software that consumes osquery-shaped rows. To
move a whole timeline into another system, export the case as JSONL:

```bash
rootstock-blue export jsonl <path.rsbcase> <out.jsonl>
```

Blue stops at the row conversion or JSONL file. Connect and map that output to
your Fleet or SIEM deployment separately; the project does not include a Fleet
server, query scheduler, or live osquery virtual table.
