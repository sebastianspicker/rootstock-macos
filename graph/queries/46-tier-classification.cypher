// Name: Tier Classification Summary
// Purpose: List all classified Application nodes grouped by tier, with their security-relevant properties
// Category: Blue Team
// Severity: Informational
// Parameters: none
// Prerequisites: import.py + infer.py + tier_classification.py must have run

MATCH (app:Application)
WHERE app.tier IS NOT NULL
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
OPTIONAL MATCH (app)-[:HAS_ENTITLEMENT]->(ent:Entitlement {is_private: true})

WITH app,
     collect(DISTINCT perm.display_name)   AS tcc_grants,
     collect(DISTINCT ent.name)            AS private_entitlements,
     size(app.injection_methods)           AS injection_method_count

RETURN app.tier                            AS tier,
       app.name                            AS app_name,
       app.bundle_id                       AS bundle_id,
       app.is_system                       AS is_system,
       tcc_grants,
       private_entitlements,
       injection_method_count,
       app.is_electron                     AS is_electron
ORDER BY app.tier ASC, app.name
