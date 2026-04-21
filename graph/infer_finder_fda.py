"""
infer_finder_fda.py — Infer HAS_TRANSITIVE_FDA relationships.

Apps with an allowed kTCCServiceAppleEvents TCC grant can automate Finder (or
other Apple Events targets). Because Finder has implicit Full Disk Access, any
app that can send Apple Events can transitively access files via Finder scripting.

This is an approximation: the TCC database stores the *source* app's automation
grant but does not always record the *target* app. We flag all apps with an
AppleEvents grant as having transitive FDA potential.

Edge: App -[:HAS_TRANSITIVE_FDA {inferred: true, via: 'apple_events'}]-> TCC_Permission(FDA)
"""

from __future__ import annotations

from neo4j import Session

from constants import APPLE_EVENTS_SERVICE, FDA_SERVICE


def infer(session: Session) -> int:
    """
    Infer HAS_TRANSITIVE_FDA edges from apps with AppleEvents grants to the
    FDA TCC_Permission node. Returns edge count. Idempotent.
    """
    result = session.run(
        """
        MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: $ae_service})
        WITH DISTINCT a
        MERGE (fda:TCC_Permission {service: $fda_service})
        ON CREATE SET fda.display_name = 'Full Disk Access',
                      fda.inferred = true
        MERGE (a)-[r:HAS_TRANSITIVE_FDA]->(fda)
        SET r.inferred = true,
            r.via = 'apple_events'
        RETURN count(r) AS n
        """,
        ae_service=APPLE_EVENTS_SERVICE,
        fda_service=FDA_SERVICE,
    )
    return result.single()["n"]
