"""
infer_kerberos.py — Infer CAN_READ_KERBEROS relationships.

Creates edges from injectable Applications to KerberosArtifact nodes when the
app could plausibly read the artifact.  Four rules:

1. Injectable FDA app → CAN_READ_KERBEROS any artifact on the same host
   (Full Disk Access grants read to all files)
2. Injectable app owned by the same user as a ccache → CAN_READ_KERBEROS
   that ccache (same-UID read)
3. World-readable artifact → any injectable app CAN_READ_KERBEROS
   (misconfigured permissions)
4. Group-readable artifact → injectable app whose user is in the same group
   CAN_READ_KERBEROS (POSIX group-read access)

All inferred edges carry {inferred: true} to distinguish from explicit data.
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID


def _infer_fda_reads(session: Session) -> int:
    """Rule 1: Injectable app with FDA → can read any KerberosArtifact."""
    result = session.run(
        """
        MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(t:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        WHERE size(a.injection_methods) > 0
          AND NOT coalesce(a.is_sip_protected, false)
          AND a.bundle_id <> $attacker_id
        WITH DISTINCT a
        MATCH (ka:KerberosArtifact)
        MERGE (a)-[r:CAN_READ_KERBEROS]->(ka)
        SET r.inferred = true, r.method = 'fda'
        RETURN count(r) AS n
        """,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]


def _infer_same_user_reads(session: Session) -> int:
    """Rule 2: Injectable app whose running user owns a ccache → can read it.

    Constrains the app to the ccache owner via the LaunchItem RUNS_AS
    relationship, ensuring the app actually runs as the user who owns
    the ccache. Without this constraint, any injectable app with a TCC
    grant would be linked to every ccache on the same host.
    """
    result = session.run(
        """
        MATCH (u:User)-[:HAS_KERBEROS_CACHE]->(ka:KerberosArtifact)
        MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        WHERE size(a.injection_methods) > 0
          AND NOT coalesce(a.is_sip_protected, false)
          AND a.bundle_id <> $attacker_id
        WITH DISTINCT a, ka, u
        MATCH (a)-[:INSTALLED_ON]->(:Computer)<-[:FOUND_ON]-(ka)
        WHERE ka.owner = u.name
          AND EXISTS {
              MATCH (a)-[:PERSISTS_VIA]->(:LaunchItem)-[:RUNS_AS]->(u)
          }
        MERGE (a)-[r:CAN_READ_KERBEROS]->(ka)
        SET r.inferred = true, r.method = 'same_user'
        RETURN count(r) AS n
        """,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]


def _infer_world_readable(session: Session) -> int:
    """Rule 3: World-readable artifact → any injectable app on the same host can read it."""
    result = session.run(
        """
        MATCH (ka:KerberosArtifact {is_world_readable: true})
        MATCH (ka)-[:FOUND_ON]->(c:Computer)
        MATCH (a:Application)-[:INSTALLED_ON]->(c)
        WHERE size(a.injection_methods) > 0
          AND NOT coalesce(a.is_sip_protected, false)
          AND a.bundle_id <> $attacker_id
        WITH DISTINCT a, ka
        MERGE (a)-[r:CAN_READ_KERBEROS]->(ka)
        SET r.inferred = true, r.method = 'world_readable'
        RETURN count(r) AS n
        """,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]


def _infer_group_readable(session: Session) -> int:
    """Rule 4: Group-readable artifact → injectable app on same host whose user is in the group."""
    result = session.run(
        """
        MATCH (ka:KerberosArtifact {is_group_readable: true})
        WHERE ka.group_name IS NOT NULL
        MATCH (ka)-[:FOUND_ON]->(c:Computer)
        MATCH (lg:LocalGroup {name: ka.group_name})
        MATCH (u:User)-[:MEMBER_OF]->(lg)
        MATCH (a:Application)-[:INSTALLED_ON]->(c)
        WHERE size(a.injection_methods) > 0
          AND NOT coalesce(a.is_sip_protected, false)
          AND a.bundle_id <> $attacker_id
        WITH DISTINCT a, ka
        MERGE (a)-[r:CAN_READ_KERBEROS]->(ka)
        SET r.inferred = true, r.method = 'group_readable'
        RETURN count(r) AS n
        """,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]


def infer(session: Session) -> int:
    """
    Infer all CAN_READ_KERBEROS relationships. Returns total edge count.
    Idempotent: uses MERGE, safe to re-run.
    """
    total = 0
    total += _infer_fda_reads(session)
    total += _infer_same_user_reads(session)
    total += _infer_world_readable(session)
    total += _infer_group_readable(session)
    return total
