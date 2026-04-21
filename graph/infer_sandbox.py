"""
infer_sandbox.py — Infer sandbox-related attack relationships.

Creates two types of edges:

1. CAN_ESCAPE_SANDBOX: A sandboxed app with unconstrained file read or
   unconstrained network access AND injection vectors could be leveraged
   to escape sandbox constraints.

2. CAN_ACCESS_MACH_SERVICE: A sandboxed app's mach-lookup rules match
   an XPC service label, indicating the sandbox allows IPC to that service.

All inferred edges carry {inferred: true} to distinguish from explicit data.
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID


def _infer_sandbox_escape(session: Session) -> int:
    """
    Sandboxed injectable apps with unconstrained network or file read
    are potential sandbox escape vectors.

    These apps have sandbox profiles that grant broad access despite being
    sandboxed, making them high-value injection targets.
    """
    result = session.run(
        """
        MATCH (a:Application)-[:HAS_SANDBOX_PROFILE]->(sp:SandboxProfile)
        WHERE (sp.has_unconstrained_network = true OR sp.has_unconstrained_file_read = true)
          AND size(a.injection_methods) > 0
          AND NOT coalesce(a.is_sip_protected, false)
          AND a.bundle_id <> $attacker_id
        WITH DISTINCT a, sp
        MATCH (attacker:Application {bundle_id: $attacker_id})
        MERGE (attacker)-[r:CAN_ESCAPE_SANDBOX]->(a)
        SET r.inferred = true,
            r.has_unconstrained_network = sp.has_unconstrained_network,
            r.has_unconstrained_file_read = sp.has_unconstrained_file_read,
            r.exception_count = sp.exception_count
        RETURN count(r) AS n
        """,
        attacker_id=ATTACKER_BUNDLE_ID,
    )
    return result.single()["n"]


def _infer_mach_service_access(session: Session) -> int:
    """
    Sandboxed apps whose mach-lookup rules list an XPC service label
    can communicate with that service from within the sandbox.

    This is significant because XPC services often run with elevated
    privileges, and a sandbox mach-lookup exception creates a bridge
    from the sandboxed app to the privileged service.
    """
    result = session.run(
        """
        MATCH (a:Application)-[:HAS_SANDBOX_PROFILE]->(sp:SandboxProfile)
        WHERE size(sp.mach_lookup_rules) > 0
        UNWIND sp.mach_lookup_rules AS rule
        MATCH (xpc:XPC_Service)
        WHERE any(svc IN xpc.mach_services WHERE svc = rule)
        MERGE (a)-[r:CAN_ACCESS_MACH_SERVICE]->(xpc)
        SET r.inferred = true,
            r.sandbox_rule = rule
        RETURN count(r) AS n
        """,
    )
    return result.single()["n"]


def infer(session: Session) -> int:
    """
    Infer all sandbox-related attack relationships.
    Returns total edge count. Idempotent: uses MERGE, safe to re-run.
    """
    total = 0
    total += _infer_sandbox_escape(session)
    total += _infer_mach_service_access(session)
    return total
