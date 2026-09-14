# Detection content

Each detection rule is a YAML file paired with a synthetic JSONL fixture in the
ruleset's `fixtures/` directory. Name the fixture in the rule's `fixture`
field. `make content-validate` checks that the file exists.

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

To evaluate each rule against its named fixture:

```bash
rootstock-blue detect run --ruleset samples
```

To evaluate the same rules against events in a case:

```bash
rootstock-blue detect run --ruleset samples --case ./incident.rsbcase
```

Keep matching conditions explicit and reviewable. Add only synthetic host data
to the repository.
