# Severity mapping

The components retain their native severity values. Family bridges may add a
normalized value, but must preserve the original value and provenance.

## Compare values carefully

Red findings carry a severity and may also carry confidence and an OPSEC
score. Blue detections and hardening results use their own content-defined
severity or priority. Keep those fields separate when importing or reporting.

Core application inference sets `risk_level` from its computed score:

| Core score | `risk_level` |
| --- | --- |
| 7 or higher | `critical` |
| 5 to below 7 | `high` |
| 3 to below 5 | `medium` |
| Below 3 | `low` |

The score is capped at 10. These thresholds come from
[`infer_risk_score.py`](../../graph/src/rootstock_graph/inference/infer_risk_score.py);
they are not a conversion formula for Red or Blue severity. Core tier labels
are another classification and should also remain separate.

## Preserve the original evidence

When translating a family artifact:

- preserve the original severity string;
- preserve confidence, score, tier, and component provenance;
- record any normalized value as an additional field;
- avoid converting absence of evidence into a lower severity.

Reports should explain the evidence and its source before emphasizing a
severity label. See [Viewer design](../../DESIGN.md).
