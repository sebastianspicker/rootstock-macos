// Name: Unconstrained Injectable Applications
// Purpose: Find injectable apps without launch constraints — easiest targets for code injection
// Category: Red Team
// Severity: Critical
// Parameters: none
// Attack: Apps without launch constraints (macOS 13+) can be freely injected via DYLD_INSERT_LIBRARIES
// Prerequisites: import.py + infer.py must have run

MATCH (attacker:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(target:Application)
WHERE coalesce(target.launch_constraint_category, 'unconstrained') = 'unconstrained'
OPTIONAL MATCH (target)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
RETURN target.name                         AS app_name,
       target.bundle_id                    AS bundle_id,
       target.launch_constraint_category   AS constraint_category,
       collect(DISTINCT inj.method)        AS injection_methods,
       collect(DISTINCT perm.display_name) AS tcc_grants,
       size(collect(DISTINCT perm))        AS grant_count
ORDER BY grant_count DESC, target.name
