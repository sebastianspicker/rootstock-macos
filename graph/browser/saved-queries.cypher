// ============================================================
// Rootstock — Saved Queries for Neo4j Browser
// ============================================================
// Usage: Paste any query into Neo4j Browser and click Run.
//        Or use the star icon (☆) in Neo4j Browser to save
//        queries to your local Favorites after running them.
//
// Import tip: Neo4j Browser does not have a CLI import for
// favorites — star (☆) each query after running it once to
// add it to your sidebar Favorites panel.
// ============================================================


// ── ★ KILLER QUERY 1 — Injectable FDA Apps ───────────────────────────────
// Severity: Critical
// Find all apps with Full Disk Access that can be code-injected by an attacker.
// Attack: Inject dylib → inherit Full Disk Access → read TCC.db, SSH keys, Mail.

MATCH (app:Application)
      -[:HAS_TCC_GRANT {allowed: true}]->
      (:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
MATCH (:Application {bundle_id: 'attacker.payload'})-[inj:CAN_INJECT_INTO]->(app)
WITH app, collect(DISTINCT inj.method) AS injection_methods
RETURN app.name            AS app_name,
       app.bundle_id       AS bundle_id,
       app.path            AS path,
       app.team_id         AS team_id,
       injection_methods,
       size(injection_methods) AS method_count
ORDER BY method_count DESC, app.name ASC;


// ── ★ KILLER QUERY 2 — Shortest Path to Full Disk Access ─────────────────
// Severity: Critical
// Find the minimum-hop chain from attacker payload to Full Disk Access.

MATCH (attacker:Application {bundle_id: 'attacker.payload'}),
      (fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
MATCH p = shortestPath((attacker)-[*..5]->(fda))
RETURN p,
       length(p)                                                AS path_length,
       [n IN nodes(p) | coalesce(n.name, n.display_name, '?')] AS node_names,
       [r IN relationships(p) | type(r)]                        AS rel_types
ORDER BY path_length ASC
LIMIT 10;


// ── ★ KILLER QUERY 3 — Electron TCC Inheritance ──────────────────────────
// Severity: High
// Which Electron apps pass TCC permissions to child processes via ELECTRON_RUN_AS_NODE?

MATCH (app:Application {is_electron: true})-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH app, collect(DISTINCT perm.display_name) AS inherited_permissions
RETURN app.name              AS app_name,
       app.bundle_id         AS bundle_id,
       app.path              AS path,
       inherited_permissions,
       size(inherited_permissions) AS permission_count
ORDER BY permission_count DESC, app.name ASC;


// ── ★ KILLER QUERY 4 — Private Entitlement Audit ─────────────────────────
// Severity: High
// Third-party apps with private Apple entitlements — high-value injection targets.

MATCH (app:Application {is_system: false})-[:HAS_ENTITLEMENT]->(ent:Entitlement {is_private: true})
WITH app, collect(DISTINCT ent.name) AS private_entitlements
RETURN app.name                          AS app_name,
       app.bundle_id                     AS bundle_id,
       app.signed                        AS signed,
       app.team_id                       AS team_id,
       private_entitlements,
       size(app.injection_methods) > 0   AS is_injectable,
       app.injection_methods             AS injection_methods,
       size(private_entitlements)        AS private_ent_count
ORDER BY private_ent_count DESC, app.name ASC;


// ── ★ KILLER QUERY 5 — Apple Event TCC Cascade ───────────────────────────
// Severity: High
// Apps that gain TCC access transitively via Apple Event automation.

MATCH (source:Application)-[:CAN_SEND_APPLE_EVENT]->(target:Application)
      -[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WHERE NOT (source)-[:HAS_TCC_GRANT {allowed: true}]->(perm)
  AND source.bundle_id <> 'attacker.payload'
  AND target.bundle_id <> 'attacker.payload'
RETURN source.name                           AS source_app,
       source.bundle_id                     AS source_bundle_id,
       target.name                          AS target_app,
       perm.display_name                    AS permission_gained,
       perm.service                         AS permission_service,
       size(source.injection_methods) > 0  AS source_is_injectable
ORDER BY source.name ASC, perm.display_name ASC;


// ── ★ KILLER QUERY 6 — Multi-hop Injection Chain ─────────────────────────
// Severity: Critical
// Chains of injectable apps leading to high-value TCC permissions.

MATCH path = (attacker:Application {bundle_id: 'attacker.payload'})
             -[:CAN_INJECT_INTO*1..3]->
             (target:Application)-[:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WHERE perm.service IN [
    'kTCCServiceSystemPolicyAllFiles',
    'kTCCServiceAccessibility',
    'kTCCServiceScreenCapture',
    'kTCCServiceEndpointSecurityClient',
    'kTCCServiceListenEvent'
]
WITH path, target, perm,
     [n IN nodes(path) | coalesce(n.name, n.display_name, '?')] AS chain,
     length(path) AS hops
RETURN chain, target.name AS terminal_app, perm.display_name AS terminal_permission, hops
ORDER BY hops ASC, perm.display_name ASC
LIMIT 20;


// ── ★ KILLER QUERY 7 — TCC Grant Overview ────────────────────────────────
// Severity: Informational / Blue Team
// Full distribution of TCC grants across all services.

MATCH (app:Application)-[r:HAS_TCC_GRANT]->(perm:TCC_Permission)
WITH perm.display_name AS permission,
     perm.service      AS service,
     sum(CASE WHEN r.allowed = true  THEN 1 ELSE 0 END) AS allowed_count,
     sum(CASE WHEN r.allowed = false THEN 1 ELSE 0 END) AS denied_count,
     count(*) AS total_grants
RETURN permission, service, allowed_count, denied_count, total_grants
ORDER BY total_grants DESC;


// ── ★ KILLER QUERY 8 — Persistence Audit ─────────────────────────────────
// Severity: High
// Third-party LaunchDaemons/Agents that run as root or are linked to injectable apps.

MATCH (l:LaunchItem)
WHERE l.type IN ['daemon', 'agent']
  AND NOT l.label STARTS WITH 'com.apple.'
  AND NOT l.path STARTS WITH '/System/'
OPTIONAL MATCH (l)-[:RUNS_AS]->(u:User)
OPTIONAL MATCH (a:Application)-[:PERSISTS_VIA]->(l)
WITH l, u, a,
     CASE WHEN u.name = 'root' OR (l.type = 'daemon' AND u IS NULL) THEN true ELSE false END AS runs_as_root,
     CASE WHEN a IS NOT NULL AND size(a.injection_methods) > 0 THEN true ELSE false END AS app_is_injectable
WHERE runs_as_root = true OR app_is_injectable = true
RETURN l.label AS label, l.type AS type, l.program AS program,
       COALESCE(u.name, 'root') AS runs_as, a.name AS app_name,
       runs_as_root, app_is_injectable
ORDER BY runs_as_root DESC, app_is_injectable DESC, l.label
LIMIT 50;


// ── ★ KILLER QUERY 9 — Keychain ACL Audit ────────────────────────────────
// Severity: High
// Applications with direct Keychain read access (no user prompt required).

MATCH (a:Application)-[:CAN_READ_KEYCHAIN]->(k:Keychain_Item)
WITH a, k, size(a.injection_methods) > 0 AS app_is_injectable
RETURN a.name AS app_name, a.bundle_id AS bundle_id,
       k.label AS keychain_label, k.kind AS kind, k.service AS service,
       app_is_injectable
ORDER BY app_is_injectable DESC, a.name, k.kind, k.label
LIMIT 100;


// ── ★ KILLER QUERY 10 — MDM-Managed TCC ─────────────────────────────────
// Severity: High
// TCC permissions silently enforced via MDM (cannot be revoked by user).

MATCH (m:MDM_Profile)-[c:CONFIGURES]->(t:TCC_Permission)
OPTIONAL MATCH (a:Application {bundle_id: c.bundle_id})
WITH m, c, t, a, a IS NOT NULL AND size(a.injection_methods) > 0 AS app_is_injectable
RETURN m.identifier AS profile_identifier, m.display_name AS profile_name,
       c.bundle_id AS target_bundle_id, a.name AS app_name,
       t.service AS tcc_service, c.allowed AS mdm_allowed, app_is_injectable
ORDER BY app_is_injectable DESC, m.identifier, c.bundle_id
LIMIT 100;


// ════════════════════════════════════════════════════════════
// EXPLORATORY QUERIES
// ════════════════════════════════════════════════════════════


// ── ★ EXPLORE 1 — Show All Nodes and Relationships ───────────────────────
// Quick overview of the entire graph (limited to 100 nodes).

MATCH (n)-[r]->(m)
RETURN n, r, m
LIMIT 100;


// ── ★ EXPLORE 2 — Apps with Most TCC Permissions ─────────────────────────
// Find the most-permissioned apps — potential over-privileging.

MATCH (app:Application)-[r:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH app, collect(DISTINCT perm.display_name) AS permissions
RETURN app.name            AS app_name,
       app.bundle_id       AS bundle_id,
       app.is_system       AS is_system,
       permissions,
       size(permissions)   AS permission_count
ORDER BY permission_count DESC
LIMIT 20;


// ── ★ EXPLORE 3 — Apps with Most Entitlements ────────────────────────────
// Find apps with the largest entitlement surface (higher complexity = higher risk).

MATCH (app:Application {is_system: false})-[:HAS_ENTITLEMENT]->(ent:Entitlement)
WITH app, count(ent) AS entitlement_count,
     sum(CASE WHEN ent.is_private THEN 1 ELSE 0 END) AS private_count
RETURN app.name          AS app_name,
       app.bundle_id     AS bundle_id,
       entitlement_count,
       private_count,
       app.signed        AS signed
ORDER BY private_count DESC, entitlement_count DESC
LIMIT 20;


// ── ★ EXPLORE 4 — All Inferred Attack Edges ──────────────────────────────
// Show all edges that were inferred by infer.py (attack paths, not raw data).

MATCH (a)-[r]->(b)
WHERE r.inferred = true
   OR type(r) IN ['CAN_INJECT_INTO', 'CHILD_INHERITS_TCC', 'CAN_SEND_APPLE_EVENT']
RETURN a, r, b
LIMIT 100;


// ── ★ EXPLORE 5 — TCC Grants by Scope (User vs System) ───────────────────
// Distinguish user-level TCC.db grants from system-level grants.

MATCH (app:Application)-[r:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
WITH r.scope AS scope, perm.display_name AS permission, count(*) AS grant_count
RETURN scope, permission, grant_count
ORDER BY scope, grant_count DESC;
