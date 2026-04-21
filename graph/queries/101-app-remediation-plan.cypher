// Name: Application Remediation Plan
// Purpose: All recommendations for a specific application by bundle_id
// Category: Blue Team
// Severity: Informational
// Parameters: $bundle_id
// Prerequisites: import.py + infer.py must have run
MATCH (app:Application {bundle_id: $bundle_id})-[:HAS_RECOMMENDATION]->(r:Recommendation)
OPTIONAL MATCH (r)-[:MITIGATES]->(t:AttackTechnique)
RETURN r.key AS recommendation_key,
       r.category AS category,
       r.text AS recommendation,
       r.priority AS priority,
       collect(DISTINCT t.name) AS mitigates,
       app.risk_score AS app_risk_score,
       app.risk_level AS app_risk_level
ORDER BY CASE r.priority
  WHEN 'critical' THEN 0
  WHEN 'high' THEN 1
  WHEN 'medium' THEN 2
  WHEN 'low' THEN 3
END;
