// Name: Trust Boundary Map
// Purpose: Visualize all trust relationships between apps (same team, automation, XPC)
// Category: Forensic
// Severity: Informational
// Parameters: $app_name (optional) — filter to a specific app's trust relationships
// Prerequisites: import.py + infer.py must have run
//
// Use case: Understand which apps implicitly trust each other. Trust boundaries
// define the blast radius of a compromise — if App A trusts App B, compromising
// either exposes the data accessible by both.
//
// Trust types modelled:
//   SIGNED_BY_SAME_TEAM  — same signing team (code identity trust)
//   CAN_SEND_APPLE_EVENT — automation trust
//   COMMUNICATES_WITH    — XPC service trust
//   CAN_INJECT_INTO      — injection vulnerability (unintended trust)

MATCH (a:Application)-[r]->(b)
WHERE type(r) IN ['SIGNED_BY_SAME_TEAM', 'CAN_SEND_APPLE_EVENT', 'COMMUNICATES_WITH', 'CAN_INJECT_INTO']
  AND (coalesce($app_name, a.name) = a.name OR $app_name IS NULL)
  AND a.bundle_id <> 'attacker.payload'

WITH a, type(r) AS trust_type, b,
     CASE type(r)
       WHEN 'SIGNED_BY_SAME_TEAM' THEN 'code_identity'
       WHEN 'CAN_SEND_APPLE_EVENT' THEN 'automation'
       WHEN 'COMMUNICATES_WITH'   THEN 'xpc'
       WHEN 'CAN_INJECT_INTO'     THEN 'injection_vuln'
       ELSE 'other'
     END AS trust_category

RETURN a.name                  AS source_app,
       a.bundle_id             AS source_bundle_id,
       trust_type,
       trust_category,
       CASE
         WHEN b:Application  THEN b.name
         WHEN b:XPC_Service  THEN b.label
         ELSE coalesce(b.name, b.label, '?')
       END                    AS target,
       CASE
         WHEN b:Application  THEN b.bundle_id
         ELSE null
       END                    AS target_bundle_id
ORDER BY trust_category, a.name
LIMIT 200
