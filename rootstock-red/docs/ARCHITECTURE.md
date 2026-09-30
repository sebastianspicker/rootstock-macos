# Rootstock Red architecture

Rootstock Red keeps assessment and lab behavior in separate executables and
Swift targets.

```text
rootstock-red
    collectors -> CollectedState -> checks and vectors -> Finding values
    -> report or project bundle

rootstock-red-lab
    operator and scope record + dry-run controls -> registered lab action
```

## Assessment pipeline

1. `SafetyRails` checks the local kill switch.
2. `CollectionRunner` executes registered read-only collectors for the selected
   profile and merges partial state.
3. `CheckRunner` evaluates regular checks and `rootstock.vector.*` assessments.
4. `OpsecScorer` annotates findings.
5. `AuditLog`, `ArtifactLedger`, and `ProjectBundle` record requested output.
6. `ReportWriter` renders JSON, JSONL, SARIF, or Markdown.

The assessment pipeline has no network client today. `--allow-network` records
the policy choice for a future or registered network-aware module. When TCC
blocks a collector or a proprietary store cannot be read, the pipeline records
the limitation in `CollectedState` and continues with the evidence it has.

## Module contracts

| Module type | Identifier | Contract |
|---|---|---|
| Collector | `collect.*` | Read-only host evidence into partial `CollectedState` |
| Check | `rootstock.check.*` | Pure evaluation over collected state into findings |
| Vector check | `rootstock.vector.*` | Technique-oriented assessment using the same check protocol |
| Lab action | `lab.*` | Registered only in `rootstock-red-lab`; requires operator and scope metadata and starts in dry-run mode |

## Build boundaries

Target graph (`Sources/`): `RootstockCore` <- `MacEnumKit` (collectors plus
the `Opsec/`, `Artifacts/`, `LOLBins/`, `Identity/`, `MDM/`, and `Persistence/`
families) <- `MacVulnKit` (checks and vectors) <- `RootstockRedCLI`;
`MacReportKit` depends on `RootstockCore` and is linked by the CLI. Tests are
`RootstockCoreTests`, `MacEnumKitTests`, and `RootstockLabTests`.

`rootstock-red` does not link `RootstockLab`. Only the separately built
`rootstock-red-lab` executable links the lab library, so the assessment binary
cannot dispatch a lab action.

See [finding schema](FINDING_SCHEMA.md), [module API](MODULE_API.md),
[acceptable use](../ACCEPTABLE_USE.md), and
[lab boundary](../NOT_FOR_PRODUCTION_IMPLANT.md).
