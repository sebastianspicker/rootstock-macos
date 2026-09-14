"""
infer_file_acl.py - Infer attack paths from file ACL permissions.

Creates edges:
  - (User)-[:CAN_WRITE]->(CriticalFile): user can write a security-critical file
  - (CriticalFile)-[:PROTECTS]->(TCC_Permission|Keychain_Item): file protects security resources
  - (User)-[:CAN_MODIFY_TCC]->(TCC_Permission): transitive - user can write TCC.db → modify any TCC grant

All inferred edges carry {inferred: true} to distinguish from explicit data.
"""

from __future__ import annotations

from neo4j import Session


_CAN_WRITE_RULES = (
    (
        "owner_writable",
        """
        MATCH (cf:CriticalFile)
        WHERE cf.is_writable_by_non_root = true
          AND cf.owner IS NOT NULL
        MERGE (u:User {name: cf.owner})
        """,
    ),
    (
        "group_writable",
        """
        MATCH (cf:CriticalFile)
        WHERE cf.is_group_writable = true
          AND cf.group_name IS NOT NULL
        MATCH (lg:LocalGroup {name: cf.group_name})
        MATCH (u:User)-[:MEMBER_OF]->(lg)
        """,
    ),
    (
        "world_writable",
        """
        MATCH (cf:CriticalFile)
        WHERE cf.is_world_writable = true
        MATCH (u:User)
        """,
    ),
)


def infer(session: Session) -> int:
    """
    Infer file-ACL-based attack paths. Returns total edges created.
    Idempotent: uses MERGE, safe to re-run.
    """
    total = 0

    total += _infer_can_write_edges(session)
    total += _infer_tcc_protection_edges(session)
    total += _infer_keychain_protection_edges(session)
    total += _infer_can_modify_tcc_edges(session)

    return total


def _infer_tcc_protection_edges(session: Session) -> int:
    result = session.run(
        """
        MATCH (cf:CriticalFile)
        WHERE cf.category = 'tcc_database'
        MATCH (perm:TCC_Permission)
        MERGE (cf)-[r:PROTECTS]->(perm)
        SET r.inferred = true
        RETURN count(r) AS n
        """
    )
    return result.single()["n"]


def _infer_keychain_protection_edges(session: Session) -> int:
    result = session.run(
        """
        MATCH (cf:CriticalFile)
        WHERE cf.category = 'keychain'
        MATCH (kc:Keychain_Item)
        MERGE (cf)-[r:PROTECTS]->(kc)
        SET r.inferred = true
        RETURN count(r) AS n
        """
    )
    return result.single()["n"]


def _infer_can_modify_tcc_edges(session: Session) -> int:
    result = session.run(
        """
        MATCH (u:User)-[:CAN_WRITE]->(cf:CriticalFile {category: 'tcc_database'})
        WITH u, collect(cf.path) AS tcc_paths
        MATCH (perm:TCC_Permission)
        MERGE (u)-[r:CAN_MODIFY_TCC]->(perm)
        SET r.inferred = true,
            r.via_paths = tcc_paths
        RETURN count(r) AS n
        """
    )
    return result.single()["n"]


def _infer_can_write_edges(session: Session) -> int:
    total = 0
    for reason, match_clause in _CAN_WRITE_RULES:
        result = session.run(
            f"""
            {match_clause}
            MERGE (u)-[r:CAN_WRITE]->(cf)
            SET r.inferred = true,
                r.reason = $reason
            RETURN count(r) AS n
            """,
            reason=reason,
        )
        total += result.single()["n"]
    return total
