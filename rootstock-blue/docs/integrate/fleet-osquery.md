# Fleet and osquery

`RootstockBlueIntegrations.OsqueryExport` converts event envelopes to
osquery-shaped rows for integrations that consume that schema. The CLI can
also export a case timeline as JSONL:

```bash
rootstock-blue export jsonl <path.rsbcase> <out.jsonl>
```

Rootstock Blue does not provide a Fleet server, query scheduler, or live
osquery virtual tables. Operators are responsible for transporting exported
records and mapping them to their Fleet or SIEM deployment.
