# Finding schema 1.0.0

`RootstockCore.schemaVersion` is `1.0.0`.

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
| `dryRunSafe` | boolean | True for assessment checks |
| `opsecScore` | optional integer | Annotation from 0 to 100, with higher values representing more observable assessment behavior |
| `tccDomains` | string array | Related TCC domains |
| `esfExpected` | string array | Expected Endpoint Security event names |
| `osRange` | optional string | Applicable macOS version range |

Writers support JSON arrays, one-finding-per-line JSONL, SARIF 2.1.0, and
Markdown.

Additive optional fields may be introduced within schema 1.x. Removing or
renaming a field requires a schema-major change.
