# Collector benchmarks

Use `collector/scripts/benchmark.sh` to compare collector runs on the same Mac. It runs
real host collection, so its output contains private data and belongs outside
version control.

## Run the benchmark

From the repository root:

```sh
(cd collector && swift build -c release)
bash collector/scripts/benchmark.sh
```

The script needs the release binary, Python 3, `bc`, macOS `/usr/bin/time`, and
shell tools that support its timestamp calculation. It makes three timed runs
with the collector's default modules, reads application and TCC grant counts
from the JSON, and reports duration, peak resident memory, and output size.
It then makes a fourth, verbose run for module timings.

Compare runs with the same collector version, permissions, module selection,
and application inventory. Record Full Disk Access status; missing access can
reduce both the work done and the evidence collected.

## Output files

The script writes scans and timing logs under `/tmp/rootstock-bench-*` and
appends a Markdown result table to `docs/private/benchmark-results.md`. To
change the table destination:

```sh
BENCHMARK_OUTPUT=/private/path/benchmark-results.md bash collector/scripts/benchmark.sh
```

`BENCHMARK_OUTPUT` does not change the scan and timing-log paths. The collector
refuses to overwrite an existing scan, so inspect and move previous benchmark
files before repeating a run. Protect all output: it can reveal hostnames,
applications, permissions, and local performance data.

## Performance goals

The original goals for a Mac with roughly 150 applications are:

| Metric | Goal |
| --- | --- |
| Total time | Under 30 seconds |
| Peak resident memory | Under 50 MiB |
| JSON output | Under 5 MB |

These are goals, not published measurements or automated pass thresholds.
The script reports memory in MiB and output size in KiB. Judge a change using
comparable before-and-after runs, including whether collection completed.
