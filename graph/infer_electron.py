"""
infer_electron.py — Infer CHILD_INHERITS_TCC relationships for Electron apps.

Electron apps that have allowed TCC grants are vulnerable to the ELECTRON_RUN_AS_NODE
technique: a child process spawned via the `--inspect` flag or `ELECTRON_RUN_AS_NODE`
environment variable inherits the parent's TCC permissions.

Edge: attacker.payload -[:CHILD_INHERITS_TCC {via: 'ELECTRON_RUN_AS_NODE'}]-> ElectronApp
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID
from infer_injection import ensure_attacker_node


def infer(session: Session) -> int:
    """
    Infer CHILD_INHERITS_TCC edges for all Electron apps with allowed TCC grants.
    Returns the number of edges created or merged.
    Idempotent.
    """
    ensure_attacker_node(session)
    result = session.run(
        """
        MATCH (e:Application {is_electron: true})-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        WITH DISTINCT e
        WHERE e.bundle_id <> $attacker_id
        MATCH (attacker:Application {bundle_id: $attacker_id})
        MERGE (attacker)-[r:CHILD_INHERITS_TCC {via: 'ELECTRON_RUN_AS_NODE'}]->(e)
        SET r.inferred = true
        RETURN count(r) AS n
        """,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]
