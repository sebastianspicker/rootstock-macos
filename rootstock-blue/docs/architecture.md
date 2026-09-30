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

## Source layout

Each SwiftPM target lives at `Sources/<Target>/` and its tests in
`Tests/RootstockBlueTests/`. `RootstockBlueCore` holds the event envelope, field
taxonomy, and `CaseTimestamp`, the single case-timestamp formatter.
`RootstockBlueInterchange` imports and exports contract formats (collector scan
JSON, findings JSONL, family export) and case outputs (JSONL, reports).

Surface-marker parsers in `RootstockBlueFX/Parsers/` are specs run by one
`SurfaceMarkerEngine`; add a parser as a `SurfaceMarkerSpec`, not as new
parsing code. Characterization goldens live in
`Tests/RootstockBlueTests/Fixtures/surface-markers/`; regenerate them with
`ROOTSTOCK_BLUE_RECORD_SURFACE_MARKERS=1 swift test` after an intended change.
Integration guides are in [`integrate/`](integrate/README.md). Blue-owned
scripts live in `Tools/scripts/`.

See [case package](case-package-v0.md),
[synthetic event profiles](synthetic-event-profiles.md), and
[platform limitations](limitations.md).
