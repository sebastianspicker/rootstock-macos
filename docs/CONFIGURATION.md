# Configuration

Each Rootstock tool has its own settings. This page covers environment
variables, input files, and storage shared across workflows. Start with the
component README for command examples.

## Graph and local services

| Setting | Used by | Default or requirement | Notes |
| --- | --- | --- | --- |
| `NEO4J_URI` | Graph commands and pipeline | `bolt://localhost:7687` | The API and verification lane require loopback. General graph CLIs can accept an explicit URI and therefore need a separate deployment review before remote use. |
| `NEO4J_USER` | Graph commands, pipeline, and API mutations | `neo4j` | Writer account used for graph imports, inference, and API mutation routes. |
| `NEO4J_PASSWORD` | Graph commands, pipeline, API mutations, and verification | Required unless a general CLI is explicitly run with `NEO4J_AUTH=none` | Writer password. Supply it through a private shell environment or service manager; keep it out of command history. |
| `NEO4J_READ_USER` | `rootstock-graph-api` and `scripts/verify neo4j` | Required | Separate database account for API reads. Grant only `MATCH` and `SHOW`; do not grant `WRITE` or `DBMS`. |
| `NEO4J_READ_PASSWORD` | `rootstock-graph-api` and `scripts/verify neo4j` | Required | Reader password. Keep it separate from `NEO4J_PASSWORD`; the API and Neo4j check refuse to start without it. |
| `NEO4J_AUTH` | Docker Compose and general graph CLI auth toggle | Compose expects `neo4j/<password>` | `none` disables Neo4j authentication and is unsuitable for real data. |
| `ROOTSTOCK_API_TOKEN` | `rootstock-graph-api` | Required; at least 32 bytes | One bearer token authorizes all `/api/*` reads and graph-state actions. Store it only in the live viewer session and rotate it if exposed. |
| `ROOTSTOCK_VERIFY_API_PORT` | `scripts/verify neo4j` | `18080` | Changes only the temporary loopback verification port. |
| `ROOTSTOCK_VERIFY_REQUIRE_CLEAN` | `scripts/verify release` | `0`; use `1` before tagging | Adds a clean-worktree requirement to structural release checks. |
| `ROOTSTOCK_VERIFY_CANDIDATE_INDEX` | `scripts/verify release` | `0`; use `1` only with an explicit temporary `GIT_INDEX_FILE` | Treats the staged temporary index as the candidate snapshot and requires the working tree to match it exactly. |

Copy the root `.env.example` to a private `.env` file and follow its export
instructions. The tools do not load this file automatically. A shell
`source` command executes the file as shell code, so load only a file you own
and have reviewed. Never commit the populated `.env` file.

`graph/browser/setup-browser.sh` also accepts `ROOTSTOCK_HTTP_HOST`,
`ROOTSTOCK_HTTP_PORT`, `NEO4J_BOLT`, and `NEO4J_CONTAINER` for the optional
Neo4j Browser guide server. Keep the HTTP host and Bolt endpoint loopback-only
for real data.

## Review input files before use

| Input | Owner and behavior | Trust requirement |
| --- | --- | --- |
| Collector `--modules` and output path | Selects local read-only collectors and one JSON destination | Review destination ownership; `--force` replaces only a regular file and symlinks are refused. |
| cve-scan scope YAML | Selects local paths, hosts, web targets, credentials, and budgets | Review it as executable configuration. Credential entries can name commands used for local WinRM helpers or remote SSH collection. Run only reviewed scope files from a trusted source. |
| cve-scan feed cache or mirror | Supplies vulnerability records and package coordinates | Use operator-controlled directories and review provenance; scan results inherit feed quality. |
| Red CLI flags | Select assessment profile, output, network opt-in, and lab self-attestation | `--i-am-authorized` is operator acknowledgement, not authentication or proof of authorization. Written authorization remains external. |
| Blue artifact tree and `.rsbcase` | Supplies evidence and owns custody/integrity state | Use trusted local copies. A valid checksum inventory proves internal consistency, not source authenticity. |
| Blue content YAML and fixtures | Defines collection packs, field taxonomy, and detection matching | Treat custom content as code-like input and review before use. |
| `ROOTSTOCK_BLUE_ULS_BINARY` | Selects an external unified-log parser executable | The process executes this path with its own privileges. Use an absolute, locally verified, non-writable binary from the intended upstream build; do not point it at an unreviewed wrapper or download. |

`SSH_AUTH_SOCK` is ambient host state observed by a Red collector; it is not a
Rootstock credential store. No component should write secret values into
fixtures, reports, or logs.

Developer-only performance scripts accept `BENCHMARK_OUTPUT` for collector
benchmark results and `CVE_SCAN_PERF_SCOPE`, `CVE_SCAN_PERF_OUT`, and
`CVE_SCAN_PERF_CACHE` for cve-scan smoke inputs and local output. Their defaults
write to ignored documentation-private or `/tmp` paths; they are not runtime
service settings.

## Store real evidence privately

The collector and Blue export commands write owner-only files and check for
unsafe symlinks or replacement, as described in their READMEs. Other
reports, Red project directories, cve-scan runs, Neo4j volumes, and Blue case
files can inherit permissions from the creating process and parent directory.
Create them in a private directory with a restrictive umask, avoid shared
volumes, and protect backups and disposal as confidential evidence.

The root `.gitignore` covers common output names and maintained generated
directories, including `scan.json`, `rootstock-report*`, viewer exports,
cve-scan run directories, `.rsbcase` directories, root-level databases,
release archives, and local environment files. Arbitrary filenames and database
files in arbitrary subdirectories are not guaranteed to match those rules.
Use a private output directory outside the checkout for real evidence. Ignore
rules are not an access-control mechanism.

## Network access

- The collector has no network collection path.
- `graph/pipeline.sh --refresh-cve` and
  `rootstock-graph-cve-enrichment --fetch` perform explicit feed refreshes.
- cve-scan network targets, web probes, online feed refresh, and local inventory
  are controlled by its CLI and reviewed scope file.
- Red has no current network client. `--allow-network` is an explicit policy
  input for any future or registered network-capable module, not a
  substitute for code review.
- Blue is offline by default. Optional sidecars are separate executables; the
  package includes no Endpoint Security client.

Do not expose Neo4j or the graph API through a proxy, tunnel, or non-loopback
interface for real evidence without a reviewed deployment design covering authentication, authorization,
TLS, and operation.
