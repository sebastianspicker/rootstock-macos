// Name: Top Recommendations by Affected App Count
// Purpose: Recommendations ranked by the number of applications they apply to
// Category: Blue Team
// Severity: High
// Prerequisites: import.py + infer.py must have run
MATCH (app:Application)-[:HAS_RECOMMENDATION]->(r:Recommendation)
OPTIONAL MATCH (r)-[:MITIGATES]->(t:AttackTechnique)
RETURN r.key AS recommendation_key,
       r.category AS category,
       r.text AS recommendation,
       r.priority AS priority,
       count(DISTINCT app) AS affected_apps,
       collect(DISTINCT t.technique_id)[..5] AS mitigates_techniques
ORDER BY affected_apps DESC;
