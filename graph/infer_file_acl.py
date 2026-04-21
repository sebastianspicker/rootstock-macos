"""
infer_file_acl.py — Infer attack paths from file ACL permissions.

Creates edges:
  - (User)-[:CAN_WRITE]->(CriticalFile): user can write a security-critical file
  - (CriticalFile)-[:PROTECTS]->(TCC_Permission|Keychain_Item): file protects security resources
  - (User)-[:CAN_MODIFY_TCC]->(TCC_Permission): transitive — user can write TCC.db → modify any TCC grant

All inferred edges carry {inferred: true} to distinguish from explicit data.
"""

from __future__ import annotations

from neo4j import Session


def infer(session: Session) -> int:
    """
    Infer file-ACL-based attack paths. Returns total edges created.
    Idempotent: uses MERGE, safe to re-run.
    """
    total = 0

    # 1a. CAN_WRITE: Users who own writable critical files
    result = session.run(
        """
        MATCH (cf:CriticalFile)
        WHERE cf.is_writable_by_non_root = true
          AND cf.owner IS NOT NULL
        MERGE (u:User {name: cf.owner})
        MERGE (u)-[r:CAN_WRITE]->(cf)
        SET r.inferred = true,
            r.reason = 'owner_writable'
        RETURN count(r) AS n
        """
    )
    total += result.single()["n"]

    # 1b. CAN_WRITE: Group members who can write group-writable critical files
    result = session.run(
        """
        MATCH (cf:CriticalFile)
        WHERE cf.is_group_writable = true
          AND cf.group_name IS NOT NULL
        MATCH (lg:LocalGroup {name: cf.group_name})
        MATCH (u:User)-[:MEMBER_OF]->(lg)
        MERGE (u)-[r:CAN_WRITE]->(cf)
        SET r.inferred = true,
            r.reason = 'group_writable'
        RETURN count(r) AS n
        """
    )
    total += result.single()["n"]

    # 1c. CAN_WRITE: All users can write world-writable critical files
    result = session.run(
        """
        MATCH (cf:CriticalFile)
        WHERE cf.is_world_writable = true
        MATCH (u:User)
        MERGE (u)-[r:CAN_WRITE]->(cf)
        SET r.inferred = true,
            r.reason = 'world_writable'
        RETURN count(r) AS n
        """
    )
    total += result.single()["n"]

    # 2a. PROTECTS: TCC database files protect all TCC_Permission nodes
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
    total += result.single()["n"]

    # 2b. PROTECTS: Keychain files protect all Keychain_Item nodes
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
    total += result.single()["n"]

    # 3. CAN_MODIFY_TCC: Transitive — users who can write TCC.db can modify any TCC grant.
    #    Collect all writable TCC paths per user to avoid overwriting via on MERGE.
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
    total += result.single()["n"]

    return total
