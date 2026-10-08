// Name: Top Recommendations by Affected Count
// Purpose: Every recommendation on this host (app-specific and host settings) ranked by priority and the number of apps it applies to
// Category: Blue Team
// Severity: High
// Prerequisites: rootstock-graph-import-scan + rootstock-graph-infer must have run
MATCH (subject)-[:HAS_RECOMMENDATION]->(r:Recommendation)
WHERE subject:Application OR subject:Computer
OPTIONAL MATCH (r)-[:MITIGATES]->(t:AttackTechnique)
WITH r, t,
     collect(DISTINCT CASE WHEN subject:Application THEN subject.name ELSE subject.hostname END) AS affected
RETURN r.key AS recommendation_key,
       coalesce(r.scope, 'app') AS scope,
       r.category AS category,
       coalesce(r.title, r.key) AS title,
       r.text AS recommendation,
       r.priority AS priority,
       size(affected) AS affected_count,
       affected[..10] AS affected_names,
       collect(DISTINCT t.technique_id)[..5] AS mitigates_techniques
ORDER BY CASE r.priority
  WHEN 'critical' THEN 0
  WHEN 'high' THEN 1
  WHEN 'medium' THEN 2
  WHEN 'low' THEN 3
  ELSE 4
END, affected_count DESC, title;
