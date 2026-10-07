# Quality gates

Run `sh scripts/verify <lane>` from the repository root to check a component
or workflow. CI runs the same lanes after installing the required tools and
locked dependencies.

| Lane | Runs | Requirements |
| --- | --- | --- |
| `quality` | Source-size ratchet; Ruff lint and format checks over `graph/src`, `scripts`, `graph/scripts`, `rootstock-blue/Tools/scripts`, `examples`, and `docs` (not `docs/archive` or `docs/private`), plus cve-scan; viewer `npm run lint` and `format:check`; jscpd duplication gate; SwiftLint `--strict` | `npm ci --ignore-scripts` in the repository root (jscpd) and in `graph/viewer` (Biome, ESLint), `uv`, `python3`, SwiftLint exactly 0.65.0 |
| `release` | 600-line source ceiling, `scripts/check-release.py`, then the Pages demo build and check (`graph/viewer/scripts/`) | Python 3 and Node.js; no npm install |
| `swift-core` | Collector `swift build` and `swift test --parallel`, both with complete strict concurrency and warnings as errors | Swift 6.3 |
| `swift-family` | Blue field-taxonomy check; Red build, CLI smoke, and repeatable family export; Blue build, CLI case workflow, and repeatable family export; `rootstock-graph-import-family-export --validate-only` on both exports; Red tests, `Scripts/check-no-lab-link.sh`, and lab fail-closed check; Blue tests, `make content-validate`, `make check-non-goals`, and a sample detection run; `RootstockMacFacts` build and tests; technique-catalog check | Swift, `make`, `python3`, `uv` |
| `graph` | Ruff, every graph test, `check-contracts.py`, `check-scan-contract-fields.py`, `rootstock-graph-validate-scan` on the demo scan, and the wheel smoke test | `uv` graph environment |
| `cve` | cve-scan Ruff and test suite | `uv` cve-scan environment |
| `web` | `npm run typecheck`, `npm run lint`, viewer Node tests, and the packaged-asset freshness check | `npm ci --ignore-scripts` in `graph/viewer`, `git` |
| `shell` | ShellCheck for tracked `*.sh` files and `scripts/verify` | ShellCheck |
| `neo4j` | Synthetic pipeline import, `graph/scripts/check-neo4j-connection.py`, and an authenticated loopback API graph read | Neo4j 5.x, `NEO4J_PASSWORD`, `NEO4J_READ_USER`, `NEO4J_READ_PASSWORD`, `uv`, `curl` |
| `full` | Every lane above, including `quality` and `neo4j` | All preceding requirements |

Swift test runs use Swift Testing, not XCTest, and do not need Xcode. When the
selected developer directory is the Command Line Tools, the toolchain needs
`-Xswiftc -plugin-path` for its Swift Testing macro plugin. `scripts/swift-test`
adds it and is what `scripts/verify` and `make test` in `rootstock-blue/` use;
run `sh <repo>/scripts/swift-test [args]` from a package directory for direct
test runs.

Run a focused lane for ordinary work and the broader affected lanes for shared
or contract changes:

```sh
sh scripts/verify quality
sh scripts/verify graph
sh scripts/verify swift-family
sh scripts/verify release
```

## Code quality checks

The `quality` lane reports problems without editing source. It checks:

- Ruff lint and format checks across maintained Python, all governed by the
  root `ruff.toml` (`graph/`, `scripts/`, `examples/`, `docs/`, and product
  tool scripts). `C901` fails above a McCabe complexity of 8.
  `modules/cve-scan` uses its own project configuration.
- Biome lint and format checks across authored TypeScript, JavaScript, MJS, and
  CSS, plus ESLint's classic cyclomatic-complexity limit of 8, all configured in
  `graph/viewer/`. Viewer bundles are generated from `graph/viewer/src/` and
  `graph/viewer/css/`; they are not formatted directly.
- SwiftLint 0.65.0 correctness checks, a complexity limit of 8, and a 60-line
  function-body limit. CI verifies the official
  `SwiftLintBinary.artifactbundle.zip` SHA-256 before extraction. Local runs
  may set `SWIFTLINT_BIN` to that verified executable.
- jscpd 5.4.0 with 10-line and 75-token clone minima. `.jscpd.json` isolates
  product runtimes and excludes only generated, dependency, cache, archive,
  and synthetic-fixture paths. `.jscpd-baseline.json` records accepted exact
  fingerprints; removed clones are allowed, while new clone fingerprints fail.
- A 600-line global source ceiling. `.source-size-baseline.json` records exact
  ceilings for the remaining existing 501-600-line files. Those files may
  shrink but not grow, and new maintained files may not exceed 500 lines.

The root `package.json` holds only the jscpd gate; the viewer's
`graph/viewer/package.json`, `biome.json`, and `eslint.config.mjs` define its
checks. Both Python lockfiles, `.swiftlint.yml`, `.jscpd.json`, and the two
ratchet baselines complete the set. Review the full report before changing a baseline;
raising a limit does not fix the reported issue.

## Neo4j integration

Start and configure a local database before running the `neo4j` lane. The lane
runs the synthetic pipeline against that database and reads `/api/graph`
through the authenticated API. It requires `NEO4J_PASSWORD`, `NEO4J_READ_USER`,
and `NEO4J_READ_PASSWORD`; see [Configuration](CONFIGURATION.md). It does not
start Docker. Missing services, credentials, tools, or dependencies fail the
check.

## Artifact compatibility

`sh scripts/verify graph` runs `scripts/check-contracts.py` under graph's locked
environment. That checker validates every shared schema and fixture in
`contracts/`, including invalid-fixture rejection, JSONL shape, format checks,
node/edge vocabulary, counts, and endpoint integrity. It also runs
`scripts/check-scan-contract-fields.py`, which checks that the collector
schema's top-level keys align with `rootstock_graph.models.ScanResult`, that
the graph model accepts the collector encoder fixture, and that the fixture
covers every schema property. The packaged graph contract mirrors are checked
byte-for-byte against `contracts/`. The collector's
`CompleteScanFixtureTests` (run by `swift-core`) require real encoder output to
equal that fixture.

## Release checks

`sh scripts/verify release` checks public files and the static demo. It does
not build archives or publish anything. Set `ROOTSTOCK_VERIFY_REQUIRE_CLEAN=1`
before tagging to require a clean working tree.

To check an uncommitted candidate without changing your staging area, use a
temporary `GIT_INDEX_FILE` containing the complete candidate and set both
`ROOTSTOCK_VERIFY_REQUIRE_CLEAN=1` and `ROOTSTOCK_VERIFY_CANDIDATE_INDEX=1`.
The checker requires that temporary index to match the working tree exactly.
New files still need to be included in the eventual release commit.

These checks cover local source and artifacts. Live collection, Neo4j,
external feeds, signing, and publication need their own verification. Follow
[Releasing Rootstock](RELEASING.md) when preparing a release.
