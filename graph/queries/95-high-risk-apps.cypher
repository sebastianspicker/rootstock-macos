// Name: High-Risk Applications
// Purpose: Applications with graph-native risk_score >= 7.0 (critical level)
// Category: Red Team
// Severity: Critical
// Prerequisites: import.py + infer.py must have run
MATCH (app:Application)
WHERE app.risk_score >= 7.0
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(tcc:TCC_Permission)
RETURN app.name AS app_name,
       app.bundle_id AS bundle_id,
       app.risk_score AS risk_score,
       app.risk_level AS risk_level,
       app.attack_categories AS attack_categories,
       app.critical_finding_count AS critical_findings,
       app.high_finding_count AS high_findings,
       app.tier AS tier,
       collect(DISTINCT tcc.service) AS tcc_grants
ORDER BY app.risk_score DESC;
