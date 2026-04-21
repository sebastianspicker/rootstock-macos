"""
infer_automation.py — Infer CAN_SEND_APPLE_EVENT relationships.

Apps with an allowed TCC grant for kTCCServiceAppleEvents can automate other apps
that have valuable (allowed) TCC grants. Apple Events allow cross-process control,
enabling privilege escalation via a less-protected app that has sensitive permissions.

Edge: AppWithAutomation -[:CAN_SEND_APPLE_EVENT {inferred: true}]-> ValuableTargetApp
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID, APPLE_EVENTS_SERVICE
from infer_injection import ensure_attacker_node


def infer(session: Session) -> int:
    """
    Infer CAN_SEND_APPLE_EVENT edges from apps with allowed Automation grants to
    apps that have any allowed TCC grant (valuable targets).
    Returns the number of edges created or merged.
    Idempotent.
    """
    ensure_attacker_node(session)
    # NOTE: Known approximation — this creates a Cartesian product between all
    # apps with Automation TCC grants and all apps with any TCC grant. The real
    # Apple Events automation scope is per-target (kTCCServiceAppleEvents records
    # include an indirect_object_identifier), but the collector does not yet
    # capture per-target grants. Edges carry confidence: 'inferred' so analysts
    # can filter them out when precision matters.
    result = session.run(
        """
        MATCH (a:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: $service})
        WITH DISTINCT a
        WHERE a.bundle_id <> $attacker_id
        MATCH (target:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        WITH DISTINCT a, target
        WHERE a <> target
          AND target.bundle_id <> $attacker_id
        MERGE (a)-[r:CAN_SEND_APPLE_EVENT]->(target)
        SET r.inferred = true, r.confidence = 'inferred'
        RETURN count(r) AS n
        """,
        service=APPLE_EVENTS_SERVICE,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]
