// Name: Stale Keytab Detection
// Purpose: Keytabs not rotated in over 1 year — stale keytabs indicate poor key rotation hygiene and may contain compromised credentials
// Category: Blue Team
// Severity: Informational
// Parameters: none
// Prerequisites: import.py must have run

MATCH (ka:KerberosArtifact {artifact_type: 'keytab'})
WHERE ka.modification_time IS NOT NULL
  AND datetime(ka.modification_time) < datetime() - duration({months: 12})
RETURN ka.path                    AS keytab_path,
       ka.owner                   AS owner,
       ka.group_name              AS file_group,
       ka.mode                    AS permissions,
       ka.modification_time       AS last_modified,
       duration.between(datetime(ka.modification_time), datetime()).months AS months_since_rotation,
       ka.is_world_readable       AS world_readable,
       ka.is_group_readable       AS group_readable
ORDER BY ka.modification_time ASC
