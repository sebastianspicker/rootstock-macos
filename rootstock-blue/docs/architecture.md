# Rootstock Blue architecture

The CLI and its libraries use the `.rsbcase` directory as their shared case
model:

```text
artifact tree or imported event data
    |
    v
parsers and collectors -> normalized EventEnvelope values
    |
    v
.rsbcase package -> timeline, detections, custody, export, reports
```

| Component | Role | Access |
|---|---|---|
| `rootstock-blue` CLI | Built and tested with synthetic fixtures | Runs as the current user; some read-only posture probes need access to protected paths |
| `RootstockBlueFX` | Offline parsing and hardening assessment | Reads only the mounted or copied artifact tree available to the current user |
| `RootstockBlueSyntheticEvents` | Fixture profiles and case injection | Works with supplied events and has no Endpoint Security subscription |

The package boundaries enforce these constraints:

1. The case package is the incident artifact. Format v0 detects interrupted
   writes but does not guarantee durability across power loss.
2. Synthetic event processing bounds its workload and reports dropped input.
3. `RootstockBlueSyntheticEvents` does not depend on the offline parser library.
4. Fixture profiles neither subscribe to Endpoint Security nor authorize or
   block activity.
5. Read-only local posture probes remain separate from event injection.

See [case package](case-package-v0.md),
[synthetic event profiles](synthetic-event-profiles.md), and
[platform limitations](limitations.md).
