# Santa integration

Rootstock Blue can parse Santa JSONL events into an existing case timeline:

```bash
rootstock-blue santa ingest <log.jsonl> --case <path.rsbcase>
```

`RootstockBlueIntegrations.SantaBridge` maps supported Santa execution-event
fields to Rootstock Blue event envelopes. It does not implement Santa's
MONITOR or LOCKDOWN decision engine, deploy rules, or manage Santa clients.

Santa is maintained at [northpolesec/santa](https://github.com/northpolesec/santa).
