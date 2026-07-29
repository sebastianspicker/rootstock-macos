// Name: AD Group to Local Admin Mapping
// Purpose: List AD groups mapped to a local admin group in imported host data
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import_scan.py must have run

MATCH (ag:ADGroup)-[:MAPPED_TO]->(lg:LocalGroup {name: 'admin'})
OPTIONAL MATCH (u:User)-[:MEMBER_OF]->(lg)
RETURN ag.name                     AS ad_group,
       lg.name                     AS local_group,
       collect(DISTINCT u.name)    AS local_admin_members
ORDER BY ag.name
