# Santa integration

Rootstock Blue can add supported Santa decision-log records to an existing case
timeline:

```bash
rootstock-blue santa ingest <log.jsonl> --case <path.rsbcase>
```

`RootstockBlueIntegrations.SantaBridge` accepts JSONL and simple comma-separated
decision records. It maps supported execution fields to event envelopes and can
draft a rule comment for manual review. Santa continues to own MONITOR and
LOCKDOWN decisions, rule deployment, and client management.

Santa is maintained at [northpolesec/santa](https://github.com/northpolesec/santa).
