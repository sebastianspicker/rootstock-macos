// Name: AD to macOS Identity Map
// Purpose: AD users mapped to macOS local users via SAME_IDENTITY — identifies cross-domain principal linkage for attack path analysis
// Category: Red Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run

MATCH (ad:ADUser)-[:SAME_IDENTITY]->(u:User)
OPTIONAL MATCH (u)-[:MEMBER_OF]->(lg:LocalGroup)
OPTIONAL MATCH (ad)-[:AD_MEMBER_OF]->(ag:ADGroup)
RETURN ad.name                        AS ad_principal,
       ad.domain                      AS ad_domain,
       ad.object_id                   AS ad_sid,
       ad.enabled                     AS ad_enabled,
       ad.admin_count                 AS ad_admin_count,
       u.name                         AS macos_user,
       collect(DISTINCT lg.name)      AS local_groups,
       collect(DISTINCT ag.name)      AS ad_groups
ORDER BY ad.admin_count DESC, ad.name
