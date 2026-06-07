"""
Shared helpers for graph inference modules.
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID, ATTACKER_NAME


def ensure_attacker_node(session: Session) -> None:
    """Create (or match) the synthetic attacker.payload node. Idempotent."""
    session.run(
        """
        MERGE (a:Application {bundle_id: $bundle_id})
        ON CREATE SET a.name = $name, a.is_system = false,
                      a.hardened_runtime = false, a.library_validation = false,
                      a.is_electron = false, a.signed = false,
                      a.is_sip_protected = false, a.is_sandboxed = false,
                      a.is_running = false,
                      a.injection_methods = [], a.inferred = true
        """,
        bundle_id=ATTACKER_BUNDLE_ID,
        name=ATTACKER_NAME,
    )
