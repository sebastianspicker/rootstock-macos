// Name: High-Value Target Ranking (Attack Value Score)
// Purpose: Rank all apps by weighted attack value: TCC grants × injectability × entitlements
// Category: Forensic
// Severity: Informational
// Parameters: none
// Prerequisites: import.py + infer.py must have run
//
// Scoring formula:
//   base_score    = number of allowed TCC grants (1 point each)
//   fda_bonus     = +10 if app has Full Disk Access
//   inject_bonus  = +5 per injection method available
//   private_bonus = +3 per private Apple entitlement
//   electron_mult = ×1.5 if Electron app (ELECTRON_RUN_AS_NODE amplifier)
//
// A high attack value score means: if this app is compromised, the attacker gains
// the most capability. Prioritize hardening the top-ranked apps.

MATCH (app:Application {is_system: false})
OPTIONAL MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
OPTIONAL MATCH (app)-[:HAS_ENTITLEMENT]->(ent:Entitlement {is_private: true})
OPTIONAL MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app)

WITH app,
     count(DISTINCT perm)                                          AS tcc_count,
     count(DISTINCT ent)                                           AS private_ent_count,
     collect(DISTINCT perm.service)                               AS tcc_services,
     collect(DISTINCT perm.display_name)                          AS tcc_names,
     collect(DISTINCT inj.method)                                 AS injection_methods,
     size(collect(DISTINCT inj.method))                           AS inject_method_count

// Calculate attack value score
WITH app, tcc_count, private_ent_count, tcc_services, tcc_names, injection_methods,
     toFloat(tcc_count) +
     (CASE WHEN 'kTCCServiceSystemPolicyAllFiles' IN tcc_services THEN 10.0 ELSE 0.0 END) +
     (inject_method_count * 5.0) +
     (private_ent_count * 3.0)
     AS raw_score,
     app.is_electron AS is_electron

WITH app, tcc_count, private_ent_count, tcc_names, injection_methods, is_electron,
     CASE WHEN is_electron = true THEN raw_score * 1.5 ELSE raw_score END AS attack_value

WHERE attack_value > 0

RETURN app.name                    AS app_name,
       app.bundle_id               AS bundle_id,
       app.team_id                 AS team_id,
       is_electron,
       tcc_count,
       private_ent_count,
       tcc_names,
       injection_methods,
       round(attack_value * 10) / 10 AS attack_value_score
ORDER BY attack_value_score DESC, app.name
LIMIT 25
