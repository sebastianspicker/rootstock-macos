// Name: Weak Kerberos Encryption Defaults
// Purpose: krb5.conf files permitting weak encryption types (DES, RC4) or with security-relevant misconfigurations
// Category: Blue Team
// Severity: High
// Parameters: none
// Prerequisites: import.py must have run

MATCH (ka:KerberosArtifact {artifact_type: 'config'})
WHERE ka.permitted_enc_types IS NOT NULL
WITH ka,
     [et IN ka.permitted_enc_types WHERE et CONTAINS 'des' OR et CONTAINS 'rc4' OR et CONTAINS 'arcfour'] AS weak_types
WHERE size(weak_types) > 0
   OR ka.is_forwardable = true
RETURN ka.path                    AS config_path,
       ka.default_realm           AS default_realm,
       ka.permitted_enc_types     AS permitted_enc_types,
       weak_types                 AS weak_enc_types,
       ka.is_forwardable          AS forwardable,
       ka.realm_names             AS configured_realms,
       ka.owner                   AS file_owner,
       ka.mode                    AS file_mode
ORDER BY size(weak_types) DESC
