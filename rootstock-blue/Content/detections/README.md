# Detection content

Every detection YAML file must name a synthetic JSONL fixture in the adjacent
`fixtures/` directory. `make content-validate` fails when that fixture is
missing.

## Format

```yaml
id: sample.rule_id
title: Human title
severity: low|medium|high|critical
description: Factual description
attack_techniques:
  - T0000
match:
  event_type: NOTIFY_EXEC
  field_equals:
    process.code_signature.signed: "false"
  field_contains:
    file.path: "/Library/LaunchAgents/"
fixture: my_fixture.jsonl
atomic_mapping: optional ART id
```

Fixture mode evaluates the rule's named fixture:

```bash
rootstock-blue detect run --ruleset samples
```

Case mode evaluates events already written to a case:

```bash
rootstock-blue detect run --ruleset samples --case ./incident.rsbcase
```

Rules must state inspectable matching conditions. They must not depend on real
host data committed to the repository.
