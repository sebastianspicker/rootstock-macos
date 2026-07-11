# Rootstock Collector Performance Benchmark

This page defines the public benchmark method and acceptance targets. It does
not contain maintainer hostnames, local application inventories, or other
machine-derived results. Run data is written to the ignored local file
`docs/private/benchmark-results.md` by default.

## Targets

| Metric | Target | Notes |
|---|---|---|
| Total time | < 30s | For ~150 apps with all modules enabled |
| Peak memory | < 50 MB | Measured via `time -l` maximum resident set size |
| JSON output | < 5 MB | Typical developer Mac |

## Method

```bash
(cd collector && swift build -c release)
bash scripts/benchmark.sh
```

The benchmark runs the release collector three times, validates the resulting
JSON structure, reports duration and output size, and performs one verbose run
for module timing. Full Disk Access and enabled modules materially affect the
result, so comparisons must use the same permissions and module set.

To write results somewhere else, set an explicit local path:

```bash
BENCHMARK_OUTPUT=/tmp/rootstock-benchmark.md bash scripts/benchmark.sh
```

Do not commit benchmark output: it can reveal hostnames, application inventory,
permission state, and machine-specific performance data.
