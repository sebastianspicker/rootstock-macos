"""
infer_quarantine.py — Infer Gatekeeper bypass relationships from quarantine attributes.

Creates BYPASSED_GATEKEEPER edges from the attacker node to applications that:
  - Are not notarized (is_notarized = false)
  - Lack the quarantine flag (has_quarantine_flag = false)
  - Are not system apps (is_system = false)
  - Are not SIP-protected (is_sip_protected = false)

These apps bypassed the entire Gatekeeper download protection chain, which is a
significant security concern (ref: CVE-2022-42821 "Achilles", CVE-2024-44175).

All inferred edges carry {inferred: true} to distinguish from explicit data.
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID
from infer_injection import ensure_attacker_node


def infer(session: Session) -> int:
    """
    Infer BYPASSED_GATEKEEPER edges for apps missing both notarization and quarantine.

    An application that is not notarized AND lacks a quarantine flag indicates it
    was either sideloaded without Gatekeeper enforcement or the quarantine attribute
    was stripped — both indicate a bypass of the download defence chain.

    Returns edge count. Idempotent: uses MERGE, safe to re-run.
    """
    ensure_attacker_node(session)
    result = session.run(
        """
        MATCH (a:Application)
        WHERE coalesce(a.is_notarized, false) = false
          AND coalesce(a.has_quarantine_flag, false) = false
          AND NOT coalesce(a.is_system, false)
          AND NOT coalesce(a.is_sip_protected, false)
          AND a.bundle_id <> $attacker_id
        WITH DISTINCT a
        MATCH (attacker:Application {bundle_id: $attacker_id})
        MERGE (attacker)-[r:BYPASSED_GATEKEEPER]->(a)
        SET r.inferred = true,
            r.is_notarized = coalesce(a.is_notarized, false),
            r.has_quarantine_flag = coalesce(a.has_quarantine_flag, false),
            r.quarantine_agent = a.quarantine_agent
        RETURN count(r) AS n
        """,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]
