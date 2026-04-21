// Name: AD Group to Local Admin Mapping
// Purpose: AD groups mapped to local admin — compromising the AD group grants local admin on every AD-bound Mac
// Category: Red Team
// Severity: Critical
// Parameters: none
// Prerequisites: import.py must have run

MATCH (ag:ADGroup)-[:MAPPED_TO]->(lg:LocalGroup {name: 'admin'})
OPTIONAL MATCH (u:User)-[:MEMBER_OF]->(lg)
RETURN ag.name                     AS ad_group,
       lg.name                     AS local_group,
       collect(DISTINCT u.name)    AS local_admin_members
ORDER BY ag.name
