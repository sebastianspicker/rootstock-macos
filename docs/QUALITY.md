# Quality gates

Run `sh scripts/verify <lane>` from the repository root to check a component
or workflow. CI runs the same lanes after installing the required tools and
locked dependencies.

| Lane | Checks | Requirements |
| --- | --- | --- |
| `quality` | Formatting, lint, complexity, duplication, and source-size ratchets | Locked Python and npm environments plus SwiftLint 0.65.0 |
| `release` | Source size, release files, version agreement, and static demo | Python 3 and Node.js |
| `swift-core` | Collector strict-concurrency build and tests | Swift 6.3 |
| `swift-family` | Shared facts, Red, and Blue tests plus safety/content smoke checks | Swift and `make` |
| `graph` | Ruff, every graph test, canonical contract fixtures, scan field alignment, demo-scan validation | `uv` graph environment |
| `cve` | cve-scan Ruff and test suite | `uv` cve-scan environment |
| `web` | Viewer types, lint, Node tests, and packaged-asset comparison | npm dependencies |
| `shell` | ShellCheck for tracked shell sources and the verifier | ShellCheck |
| `neo4j` | Synthetic import, inference, connectivity, and authenticated loopback API graph read | Neo4j 5.x, writer and reader credentials, `uv`, `curl` |
| `full` | Every lane, including quality and Neo4j | All preceding requirements |

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

- Ruff lint and format checks across maintained Python. `C901` fails above a
  McCabe complexity of 8.
- Biome lint and format checks across authored TypeScript, JavaScript, MJS, and
  CSS, plus ESLint's classic cyclomatic-complexity limit of 8. Viewer bundles
  are generated from `graph/viewer-src/` and `graph/viewer-css/`; they are not
  formatted directly.
- SwiftLint 0.65.0 correctness checks, a complexity limit of 8, and a 60-line
  function-body limit. CI verifies the official
  `SwiftLintBinary.artifactbundle.zip` SHA-256 before extraction. Local runs
  may set `SWIFTLINT_BIN` to that verified executable.
- jscpd 5.1.2 with 10-line and 75-token clone minima. `.jscpd.json` isolates
  product runtimes and excludes only generated, dependency, cache, archive,
  and synthetic-fixture paths. `.jscpd-baseline.json` records accepted exact
  fingerprints; removed clones are allowed, while new clone fingerprints fail.
- A 600-line global source ceiling. `.source-size-baseline.json` records exact
  ceilings for the remaining existing 501-600-line files. Those files may
  shrink but not grow, and new maintained files may not exceed 500 lines.

`package.json`, both Python lockfiles, `.swiftlint.yml`, `.jscpd.json`, and the
two ratchet baselines define these checks. Review the full report before changing a baseline;
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
`scripts/check-scan-contract-fields.py` to align the legacy collector schema,
Swift coding keys, and `rootstock_graph.models.ScanResult` aliases.

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
