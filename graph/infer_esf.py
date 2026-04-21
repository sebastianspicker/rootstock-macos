"""
infer_esf.py — Infer Endpoint Security Framework client blinding paths.

Apps with com.apple.developer.endpoint-security.client entitlement are ESF
clients — they receive system-wide security events (process exec, file open,
network connect, etc.). If an ESF client is injectable, an attacker can
disable or manipulate security monitoring.

Edge: InjectableApp -[:CAN_BLIND_MONITORING {inferred: true}]-> SystemExtension
      (where the SystemExtension is of type endpoint_security)

Also enriches monitoring gap detection: sets `has_monitoring_gap` on
SystemExtension nodes when critical ESF events have no active listener.
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID

_ESF_ENTITLEMENT = "com.apple.developer.endpoint-security.client"

# Critical ESF event types that should be monitored by at least one extension
_CRITICAL_ESF_EVENTS = [
    "AUTH_EXEC", "AUTH_OPEN", "AUTH_KEXTLOAD", "AUTH_MOUNT", "AUTH_SIGNAL",
    "NOTIFY_EXEC", "NOTIFY_FORK", "NOTIFY_EXIT", "NOTIFY_CREATE", "NOTIFY_WRITE",
    "NOTIFY_RENAME", "NOTIFY_LINK", "NOTIFY_UNLINK", "NOTIFY_MMAP",
    "NOTIFY_KEXTLOAD", "NOTIFY_MOUNT", "NOTIFY_UNMOUNT",
]


def infer(session: Session) -> int:
    """
    Infer CAN_BLIND_MONITORING edges from injectable apps with ESF entitlement
    to SystemExtension nodes of type endpoint_security.

    Also detects monitoring gaps — critical ESF events with no active listener.

    Returns the number of edges created or merged. Idempotent.
    """
    result = session.run(
        """
        MATCH (a:Application)-[:HAS_ENTITLEMENT]->(:Entitlement {name: $esf_ent})
        WHERE size(a.injection_methods) > 0
          AND a.bundle_id <> $attacker_id
        WITH DISTINCT a
        MATCH (se:SystemExtension {extension_type: 'endpoint_security', enabled: true})
        WHERE se.bundle_id = a.bundle_id
           OR se.containing_app_bundle_id = a.bundle_id
        MERGE (a)-[r:CAN_BLIND_MONITORING]->(se)
        SET r.inferred = true,
            r.reason = 'injectable_esf_client'
        RETURN count(r) AS n
        """,
        esf_ent=_ESF_ENTITLEMENT,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    n_blind = result.single()["n"]

    # Detect monitoring gaps: set has_monitoring_gap on ESF extensions
    # that don't cover all critical events
    session.run(
        """
        MATCH (se:SystemExtension {extension_type: 'endpoint_security', enabled: true})
        WHERE se.subscribed_events IS NOT NULL
        WITH se,
             size([e IN $critical_events WHERE NOT e IN se.subscribed_events]) AS gap_count
        SET se.monitoring_gap_count = gap_count,
            se.has_monitoring_gap = gap_count > 0
        """,
        critical_events=_CRITICAL_ESF_EVENTS,
    )

    return n_blind
