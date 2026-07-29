# Severity mapping

The components retain their native severity values. Family bridges may add a
normalized value, but must preserve the original value and provenance.

| Normalized value | Red finding | Blue hardening or detection | Core graph |
|---|---|---|---|
| `critical` | `critical` | highest applicable content value | high risk-score range after inference |
| `high` | `high` | high | elevated risk-score range after inference |
| `medium` | `medium` | medium | intermediate risk-score range after inference |
| `low` | `low` | low | low risk-score range after inference |
| `info` | `info` | informational | informational report content |

This table is descriptive, not a formula for Core `risk_score`. Core scores and
tier labels are inferred after import. Red confidence and OPSEC score are
separate dimensions. Blue rule severity and hardening priority remain owned by
their source contracts.

When translating a family artifact:

- preserve the original severity string;
- preserve confidence, score, tier, and component provenance;
- record any normalized value as an additional field;
- avoid converting absence of evidence into a lower severity.

Report language follows [DESIGN.md](../../DESIGN.md), with evidence and
provenance stated before visual priority.
