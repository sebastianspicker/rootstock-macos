// Name: Application Remediation Plan
// Purpose: All recommendations for a specific application by bundle_id, with the risk reasons behind them
// Category: Blue Team
// Severity: Informational
// Parameters: $bundle_id
// Prerequisites: rootstock-graph-import-scan + rootstock-graph-infer must have run
MATCH (app:Application {bundle_id: $bundle_id})-[:HAS_RECOMMENDATION]->(r:Recommendation)
OPTIONAL MATCH (r)-[:MITIGATES]->(t:AttackTechnique)
RETURN r.key AS recommendation_key,
       r.category AS category,
       coalesce(r.title, r.key) AS title,
       r.text AS recommendation,
       r.priority AS priority,
       collect(DISTINCT t.name) AS mitigates,
       app.risk_score AS app_risk_score,
       app.risk_level AS app_risk_level,
       app.risk_reasons AS app_risk_reasons
ORDER BY CASE r.priority
  WHEN 'critical' THEN 0
  WHEN 'high' THEN 1
  WHEN 'medium' THEN 2
  WHEN 'low' THEN 3
END;
