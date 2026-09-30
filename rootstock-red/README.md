# Rootstock Red

Rootstock Red is a Swift toolkit for authorized macOS security assessment. Its
main executable, `rootstock-red`, collects host posture and reports structured
findings. The separate `rootstock-red-lab` executable provides reversible
technique-validation actions for controlled environments. Lab commands ask the
operator to identify themselves and the engagement, but the software cannot
verify written authorization.

> Rootstock Red is alpha software at version `0.1.0`. Finding schemas,
> identifiers, CLI output, and lab behavior may change between releases.

## What it does

- Host, protection, security-product, persistence, TCC/FDA, identity, MDM,
  code-signing, entitlement, browser-path, and network-sharing assessment
- Structured findings with evidence, ATT&CK identifiers, and OPSEC annotations
- JSON, JSONL, SARIF, and Markdown output
- Project directories with an artifact ledger
- Registered read-only checks and technique-oriented vector assessments
- An optional family export that the core graph can validate and import
- A separately linked lab executable for dry-run validation plans and
  explicitly enabled lab actions

The default assessment executable does not link `RootstockLab`.

## Requirements

- macOS 13 or later
- Swift 6.2 or later
- Written authorization for any assessment target

## Build and test

Run these commands from `rootstock-red/`:

```bash
swift build
swift test --parallel
swift run rootstock-red version
```

## Assessment usage

List the available collectors, checks, and lab actions:

```bash
swift run rootstock-red list collectors
swift run rootstock-red list checks
swift run rootstock-red list vectors
```

Run a read-only assessment:

```bash
swift run rootstock-red audit --profile standard --format md
swift run rootstock-red audit --format json --output /tmp/rootstock-red-findings.json
swift run rootstock-red audit \
  --project /tmp/rootstock-red-project --format jsonl
```

The assessment executable currently has no network client. `--allow-network`
records the operator's policy choice for a future or registered network-aware
module. It is not a central network sandbox.

The kill switch prevents execution when this file exists:

```bash
mkdir -p ~/.rootstock-red
touch ~/.rootstock-red/DISABLE
```

## Family export

`export-family` converts a Red findings artifact into the optional family
bridge consumed by the core graph importer:

```bash
swift run rootstock-red export-family \
  --project /tmp/rootstock-red-project \
  --output /tmp/rootstock-red-family.json
uv run --project ../graph --locked rootstock-graph-import-family-export \
  --export /tmp/rootstock-red-family.json --validate-only
```

The export is an optional interchange file. Red does not write the core
collector's `scan.json` or connect directly to Neo4j. See the
[product family map](../docs/FAMILY.md) for the boundaries between products.

## Lab executable

The lab product is built and invoked separately:

```bash
swift run rootstock-red-lab list
swift run rootstock-red-lab run lab.persist.shellrc plan \
  --i-am-authorized --scope ENGAGEMENT-ID --operator OPERATOR
```

Lab commands require an operator name and engagement scope, and they start in
dry-run mode. These values make the invocation attributable; they do not
authenticate the operator or establish permission. Some actions accept paths
and can change local state after the operator passes `--no-dry-run`. Review the
plan and resolved paths before doing so, and run lab actions only under written
rules of engagement. The default `rootstock-red` executable cannot run them.

See [Lab boundary](NOT_FOR_PRODUCTION_IMPLANT.md) and
[Acceptable use](ACCEPTABLE_USE.md).

## Output and data handling

Findings can contain hostnames, usernames, installed software, security-product
state, paths, identity posture, and other sensitive metadata. Keep real output
out of issues, pull requests, fixtures, and screenshots. The repository's
examples and tests use synthetic values.

## Known limitations

- Checks describe evidence and modeled risk. They do not prove exploitability.
- TCC and security-product visibility varies with privileges and macOS release.
- Several collectors use path or metadata presence because proprietary formats
  are not parsed.
- OPSEC scores describe how observable an assessment action is expected to be;
  they are not detection probabilities.
- The family export is an optional interchange format. Red and the core
  collector do not share a runtime or native schema.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Finding schema](docs/FINDING_SCHEMA.md)
- [Module API](docs/MODULE_API.md)
- [Acceptable use](ACCEPTABLE_USE.md)
- [Lab boundary](NOT_FOR_PRODUCTION_IMPLANT.md)
- [Security policy](SECURITY.md)

The default executable links `RootstockCore`, `MacEnumKit` (collectors plus
opsec, artifact, LOOBin, identity, MDM, and persistence modules), `MacVulnKit`,
and `MacReportKit`.

## License

Rootstock Red is licensed under Apache-2.0. See [LICENSE](LICENSE). The
[acceptable-use policy](ACCEPTABLE_USE.md) records project safety expectations;
it does not replace or add terms to the Apache-2.0 license.
