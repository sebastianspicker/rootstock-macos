# Finding schema 1.0.0

Rootstock Red serializes findings with `RootstockCore.schemaVersion`, currently
`1.0.0`.

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable check or vector identifier |
| `title` | string | Short factual summary |
| `severity` | enum | `info`, `low`, `medium`, `high`, or `critical` |
| `confidence` | enum | `low`, `medium`, or `high` |
| `category` | enum | Owning evidence category |
| `evidence` | array | Typed evidence with optional path and hash |
| `attackTechniques` | string array | ATT&CK identifiers where applicable |
| `remediation` | string array | Operator guidance |
| `falsePositiveNotes` | optional string | Conditions that can explain the result |
| `dryRunSafe` | boolean | Whether the finding came from behavior safe to evaluate in dry-run or assessment mode |
| `opsecScore` | optional integer | Observability annotation from 0 to 100; higher values mean noisier assessment behavior |
| `tccDomains` | string array | Related TCC domains |
| `esfExpected` | string array | Expected Endpoint Security event names |
| `osRange` | optional string | Applicable macOS version range |

Report writers can produce a JSON array, one finding per line as JSONL, SARIF
2.1.0, or Markdown.

Additive optional fields may be introduced within schema 1.x. Removing or
renaming a field requires a schema-major change.
