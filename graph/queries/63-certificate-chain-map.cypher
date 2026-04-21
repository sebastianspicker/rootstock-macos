// Name: Certificate Authority Hierarchy
// Purpose: Visualize the complete CA trust chain across all applications
// Category: Blue Team
// Severity: Informational
// Parameters: none
// Prerequisites: import.py must have run

MATCH (ca:CertificateAuthority)
OPTIONAL MATCH (ca)-[:ISSUED_BY]->(parent:CertificateAuthority)
OPTIONAL MATCH (a:Application)-[:SIGNED_BY_CA]->(ca)
WITH ca, parent, count(a) AS signed_app_count
RETURN ca.common_name               AS ca_name,
       ca.sha256                    AS sha256,
       ca.is_root                   AS is_root,
       ca.organization              AS organization,
       parent.common_name           AS issuer,
       signed_app_count
ORDER BY ca.is_root DESC, signed_app_count DESC
