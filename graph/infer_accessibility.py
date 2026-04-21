"""
infer_accessibility.py — Infer Accessibility API abuse attack paths.

Apps with kTCCServiceAccessibility grants can simulate keyboard/mouse input
and read any GUI element — a superset of Apple Events. An injectable app
with Accessibility permission can control any other running application.

If the injectable app also has allowed TCC grants, it becomes a high-value
pivot: inject → control UI → access all TCC-gated resources.

Edge: InjectableA11yApp -[:CAN_CONTROL_VIA_A11Y {inferred: true}]-> ValuableTargetApp
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID


_A11Y_SERVICE = "kTCCServiceAccessibility"


def infer(session: Session) -> int:
    """
    Infer CAN_CONTROL_VIA_A11Y edges from injectable apps with Accessibility
    grants to all apps with allowed TCC grants (valuable targets).

    Accessibility API can simulate keyboard/mouse input and read any GUI
    element — it's a superset of Apple Events for GUI control.

    Returns the number of edges created or merged. Idempotent.
    """
    result = session.run(
        """
        MATCH (attacker:Application {bundle_id: $attacker_id})-[:CAN_INJECT_INTO]->(a:Application)
        MATCH (a)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: $service})
        WITH DISTINCT attacker, a
        MATCH (target:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        WHERE a <> target
          AND target.bundle_id <> $attacker_id
        WITH DISTINCT a, target
        MERGE (a)-[r:CAN_CONTROL_VIA_A11Y]->(target)
        SET r.inferred = true
        RETURN count(r) AS n
        """,
        service=_A11Y_SERVICE,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]
