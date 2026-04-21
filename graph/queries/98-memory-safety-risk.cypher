// Name: Memory Safety Risk
// Purpose: Applications affected by memory safety CWEs (buffer overflow, UAF, OOB write) with injection paths
// Category: Red Team
// Severity: Critical
// Prerequisites: import.py + infer.py + import_vulnerabilities.py must have run
MATCH (app:Application)-[:AFFECTED_BY]->(v:Vulnerability)-[:HAS_CWE]->(c:CWE)
WHERE c.category = 'memory_safety'
  AND size(app.injection_methods) > 0
RETURN app.name AS app_name,
       app.bundle_id AS bundle_id,
       app.injection_methods AS injection_methods,
       collect(DISTINCT c.cwe_id + ': ' + c.name) AS memory_safety_cwes,
       collect(DISTINCT v.cve_id) AS cves,
       app.risk_score AS risk_score
ORDER BY app.risk_score DESC;
