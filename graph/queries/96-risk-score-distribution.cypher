// Name: Risk Score Distribution
// Purpose: Histogram of risk levels across all Application nodes
// Category: Blue Team
// Severity: Informational
// Prerequisites: import.py + infer.py must have run
MATCH (app:Application)
WHERE app.risk_level IS NOT NULL
RETURN app.risk_level AS risk_level,
       count(app) AS app_count,
       round(avg(app.risk_score) * 100) / 100.0 AS avg_score,
       max(app.risk_score) AS max_score,
       min(app.risk_score) AS min_score
ORDER BY CASE app.risk_level
  WHEN 'critical' THEN 0
  WHEN 'high' THEN 1
  WHEN 'medium' THEN 2
  WHEN 'low' THEN 3
END;
