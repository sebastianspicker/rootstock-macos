# Rootstock Red architecture

Rootstock Red has separate assessment and lab executables.

```text
rootstock-red
    collectors -> CollectedState -> checks and vectors -> Finding values
    -> report or project bundle

rootstock-red-lab
    authorization and dry-run controls -> registered lab action
```

## Assessment pipeline

1. `SafetyRails` checks the local kill switch.
2. `CollectionRunner` executes registered read-only collectors for the selected
   profile and merges partial state.
3. `CheckRunner` evaluates regular checks and `rootstock.vector.*` assessments.
4. `OpsecScorer` annotates findings.
5. `AuditLog`, `ArtifactLedger`, and `ProjectBundle` record requested output.
6. `ReportWriter` renders JSON, JSONL, SARIF, or Markdown.

Network egress is disabled unless `--allow-network` is explicit. TCC denial and
unreadable proprietary stores are recorded as limited evidence rather than a
claim of complete parsing.

## Module contracts

| Module type | Identifier | Contract |
|---|---|---|
| Collector | `collect.*` | Read-only host evidence into partial `CollectedState` |
| Check | `rootstock.check.*` | Pure evaluation over collected state into findings |
| Vector check | `rootstock.vector.*` | Technique-oriented assessment using the same check protocol |
| Lab action | `lab.*` | Registered only in `rootstock-red-lab`, authorization-gated, dry-run by default |

## Build boundaries

The default executable does not link `RootstockLab`, `MacAgentKit`,
`MacTransportKit`, or `RootstockMythicAdapter`. `rootstock-red-lab` links the
lab library separately. The transport and adapter targets are source
skeletons rather than supported runtime products.

See [finding schema](FINDING_SCHEMA.md), [module API](MODULE_API.md),
[acceptable use](../ACCEPTABLE_USE.md), and
[lab boundary](../NOT_FOR_PRODUCTION_IMPLANT.md).
