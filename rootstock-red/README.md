# Rootstock Red

Rootstock Red is a Swift package for authorized macOS security assessment. The
default `rootstock-red` executable collects host posture and writes structured
findings. A separate `rootstock-red-lab` executable contains reversible
technique-validation actions with explicit authorization checks and dry-run
defaults.

> Alpha status: the package reports version `0.1.0`. Finding schemas, check and
> vector identifiers, CLI output, and lab behavior may change. It is not a C2
> framework or a production implant.

## Current capabilities

- Host, protection, security-product, persistence, TCC/FDA, identity, MDM,
  code-signing, entitlement, browser-path, and network-sharing assessment
- Structured findings with evidence, ATT&CK identifiers, and OPSEC annotations
- JSON, JSONL, SARIF, and Markdown output
- Project directories with an artifact ledger
- Registered read-only checks and path-to-impact vector assessments
- An optional family export that the core graph can validate and import
- A separately linked lab executable for authorization-gated validation plans

The default assessment executable does not link `RootstockLab`,
`MacAgentKit`, `MacTransportKit`, or `RootstockMythicAdapter`.

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

List the registered surfaces:

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

Network egress is disabled in assessment mode unless `--allow-network` is
provided.

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
python3 ../graph/import_family_export.py \
  --export /tmp/rootstock-red-family.json --validate-only
```

This bridge is explicit. Red does not emit the core collector's `scan.json` and
does not feed Neo4j by default. See [Product family](../docs/FAMILY.md).

## Lab executable

The lab product is built and invoked separately:

```bash
swift run rootstock-red-lab list
swift run rootstock-red-lab run lab.persist.shellrc plan \
  --i-am-authorized --scope ENGAGEMENT-ID --operator OPERATOR
```

Lab commands require authorization metadata and default to dry-run behavior.
Some actions can create or remove system state when an operator explicitly
selects the non-dry-run path. Use them only on systems covered by written rules
of engagement. The default `rootstock-red` binary rejects lab actions.

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
- OPSEC scores are assessment annotations, not measurements of detection
  probability.
- Transport libraries are unlinked skeletons, not supported runtime
  products.
- The family export is an optional interchange format, not a shared runtime or
  schema with the core collector.

## Architecture and extension points

- [Architecture](docs/ARCHITECTURE.md)
- [Finding schema](docs/FINDING_SCHEMA.md)
- [Module API](docs/MODULE_API.md)
- [Security policy](SECURITY.md)

The default executable links `RootstockCore`, `MacOpsecKit`, `MacArtifactKit`,
`MacEnumKit`, `MacVulnKit`, `MacLolKit`, `MacIdentityKit`, `MacMdmKit`,
`MacPersistKit`, and `MacReportKit`.

## License

Rootstock Red is licensed under Apache-2.0. See [LICENSE](LICENSE). The
[acceptable-use policy](ACCEPTABLE_USE.md) records project safety expectations;
it does not replace or add terms to the Apache-2.0 license.
