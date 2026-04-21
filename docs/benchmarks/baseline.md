# Rootstock Collector — Performance Benchmarks

Baseline measurements for the release binary on the development machine.
Generated with `scripts/benchmark.sh`.

## Targets

| Metric | Target | Notes |
|---|---|---|
| Total time | < 30s | For ~150 apps with all modules enabled |
| Peak memory | < 50 MB | Measured via `time -l` maximum resident set size |
| JSON output | < 5 MB | Typical developer Mac |

---

## Run on 2026-03-19 — macOS 26.3 Tahoe (arm64)

**Machine:** Apple Silicon (arm64), macOS 26.3 Build 25D125
**Binary:** release build (`swift build -c release`)
**Apps scanned:** 184 (across /Applications, ~/Applications, /System/Applications)
**TCC grants:** 0 (no FDA — kernel blocks TCC.db on Tahoe without Full Disk Access)

| Metric | Run 1 | Run 2 | Run 3 | Average |
|---|---|---|---|---|
| Total time (s) | 6.16 | 5.36 | 5.39 | 5.64 |
| Apps scanned | 184 | 184 | 184 | 184 |
| TCC grants | 0 | 0 | 0 | 0 |
| JSON size (KB) | 1426 | 1426 | 1426 | 1426 |
| Peak memory (MB) | 45.4 | — | — | ~45 |

**Result: PASS** — 5.64s average, 45 MB peak. Well within targets.

### Per-module timing (verbose run)

```
[TCC]          completed in 0.00s  (0 grants, 2 errors)
[Entitlements] completed in 0.15s  (184 apps, 0 errors)
[CodeSigning]  completed in 0.21s  (184 apps, 0 errors)
[XPC]          completed in 4.83s  (440 services, 3 errors)
[Persistence]  completed in 0.01s  (440 items, 4 errors)
[Keychain]     completed in 0.06s  (234 items, 0 errors)
[MDM]          completed in 0.02s  (1 profiles, 0 errors)
Total: 5.28s
```

**Updated after gap features (Groups, RemoteAccess, Firewall):**

```
[TCC]          completed in 0.03s  (0 grants, 2 errors)
[Entitlements] completed in 0.23s  (184 apps)
[CodeSigning]  completed in 0.23s  (184 apps)
[XPC]          completed in 5.23s  (440 services, 3 errors)
[Persistence]  completed in 0.04s  (440 items, 4 errors)
[Keychain]     completed in 0.10s  (234 items, 0 errors)
[MDM]          completed in 0.07s  (1 profiles, 0 errors)
[Groups]       completed in 0.13s  (8 groups, 0 errors)
[RemoteAccess] completed in 0.02s  (2 services, 0 errors)
[Firewall]     completed in 0.00s  (1 policies, 1 errors)
Total: 5.23s
```

New modules add **0.15s combined** (~3% of total). No regression.

### Bottleneck Analysis

The dominant cost is **XPC enumeration (~5s)** — reading and parsing ~440 launchd plist
files from `/Library/LaunchAgents`, `/Library/LaunchDaemons`, and per-user equivalents.
This is I/O-bound (disk reads + XML parsing). The `Security.framework` calls in
Entitlements and CodeSigning are already parallelized (TaskGroup, max 8 concurrent) and
together take only ~0.46s for 184 apps.

**Future optimization opportunity (TD-008):** XPC scanning can be parallelized using the
same TaskGroup pattern applied to app entitlement scanning. Expected speedup: ~2–3x.

### Parallelization Notes

`EntitlementDataSource` uses `withTaskGroup` with max concurrency of 8 to parallelize
`Security.framework` calls per app. On this machine, entitlement scanning of 184 apps
takes **0.15s** — approximately linear scaling from the ~1.2s sequential baseline
estimated by per-app overhead × 184 apps.

---

## Run History

_(Subsequent benchmark runs are appended below by `scripts/benchmark.sh`)_
