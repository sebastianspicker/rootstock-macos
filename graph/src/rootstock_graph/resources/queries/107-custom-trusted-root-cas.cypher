// Name: Custom Trusted Root Certificates
// Purpose: Certificates trusted in the user or admin trust-settings domain (Apple's built-in roots are not collected); a custom root can sign certificates for any website
// Category: Blue Team
// Severity: High
// Parameters: none
// ATT&CK: T1553.004
// Prerequisites: rootstock-graph-import-scan must have run (collector module trustsettings)

MATCH (c:Computer)-[:TRUSTS_CERTIFICATE]->(tc:TrustedCertificate)
OPTIONAL MATCH (tc)-[:SAME_CERTIFICATE]->(ca:CertificateAuthority)
OPTIONAL MATCH (a:Application)-[:SIGNED_BY_CA]->(:CertificateAuthority)-[:ISSUED_BY*0..4]->(ca)
WITH c, tc, collect(DISTINCT a.name) AS apps_signed_under_it
RETURN c.hostname          AS hostname,
       tc.subject          AS subject,
       tc.issuer           AS issuer,
       tc.domain           AS domain,
       tc.trust_result     AS trust_result,
       tc.custom_root      AS custom_root,
       tc.is_self_signed   AS is_self_signed,
       tc.not_after        AS not_after,
       tc.sha256           AS sha256,
       apps_signed_under_it
ORDER BY custom_root DESC, domain ASC, subject ASC
