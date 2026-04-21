"""
infer_keychain_groups.py — Infer SHARES_KEYCHAIN_GROUP edges between applications.

Applications that share a Keychain access group can read each other's stored
credentials. If one app in a shared group is injectable, the attacker can
access secrets stored by all other apps in that group.

Edge: Application -[:SHARES_KEYCHAIN_GROUP {access_group: '...'}]-> Application
"""

from __future__ import annotations

from neo4j import Session


def infer(session: Session) -> int:
    """
    Infer SHARES_KEYCHAIN_GROUP edges between applications sharing a
    Keychain_Item.access_group. Returns edge count. Idempotent.
    """
    result = session.run(
        """
        MATCH (a:Application)-[:CAN_READ_KEYCHAIN]->(k:Keychain_Item)
        WHERE k.access_group IS NOT NULL
        WITH k.access_group AS grp, collect(DISTINCT a) AS apps
        WHERE size(apps) > 1
        UNWIND apps AS a
        UNWIND apps AS b
        WITH a, b, grp WHERE a.bundle_id < b.bundle_id
        // Directed edge for MERGE idempotency (a < b ensures one canonical direction).
        // The relationship is semantically symmetric — queries MUST traverse
        // undirected: -[:SHARES_KEYCHAIN_GROUP]- (not ->).
        MERGE (a)-[r:SHARES_KEYCHAIN_GROUP {access_group: grp}]->(b)
        SET r.inferred = true
        RETURN count(r) AS n
        """
    )
    return result.single()["n"]
