// Name: Apps Signed by Non-Apple Certificate Authorities
// Purpose: Find apps whose signing chain terminates at a non-Apple root CA
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run
// ATT&CK: T1553.001

MATCH (a:Application)-[:SIGNED_BY_CA]->(leaf:CertificateAuthority)
OPTIONAL MATCH path = (leaf)-[:ISSUED_BY*0..10]->(root:CertificateAuthority {is_root: true})
WITH a, leaf, root
WHERE root IS NOT NULL
  AND root.common_name IS NOT NULL
  AND NOT root.common_name STARTS WITH 'Apple'
RETURN a.name                       AS app_name,
       a.bundle_id                  AS bundle_id,
       a.signing_certificate_cn     AS signing_certificate,
       root.common_name             AS root_ca,
       root.organization            AS root_org
ORDER BY a.name
