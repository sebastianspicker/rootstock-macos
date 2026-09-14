# Red findings JSONL to Blue bridge

Red writes one `RootstockCore.Finding` JSON object per line with
`rootstock-red/Sources/MacReportKit/JSONLReporter.swift`. The strict producer
schema is `red-finding.schema.json`; its property names follow Swift's default
`Codable` convention, including camelCase fields.

Blue's retained `FindingsJSONLImporter` reads only `id`, `title`, `severity`,
`category`, and `confidence`. It supplies defaults for missing values and does
not preserve other finding fields in the imported event.
`blue-import-input.schema.json` therefore accepts any JSON object, matching the
consumer's actual boundary rather than claiming a stricter shared evidence
model.

The importer parses every nonblank line and prepares the complete event batch
before appending anything to the case. Malformed JSON or a non-object line
aborts the import without changing the case; blank lines are ignored. The
contract checker validates the strict producer record. The consumer's more
permissive defaulting behavior does not guarantee producer fidelity.
