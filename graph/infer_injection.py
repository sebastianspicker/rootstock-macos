"""
infer_injection.py — Infer CAN_INJECT_INTO relationships.

Creates edges from a synthetic `attacker.payload` node to any Application that:
  - Has at least one allowed TCC grant (making it a valuable target), AND
  - Is missing library validation (`library_validation = false`), OR
  - Is missing hardened runtime (`hardened_runtime = false`), OR
  - Has the allow-dyld-environment-variables entitlement

Design note: CAN_INJECT_INTO edges are only created for apps with TCC grants.
This is intentional — the injection is only security-relevant when the target
has TCC permissions worth stealing. Apps without TCC grants may be technically
injectable but don't represent an attack-path escalation opportunity. The
collector still records injection_methods on all apps for completeness.

All inferred edges carry `{inferred: true}` to distinguish them from explicit data.
"""

from __future__ import annotations

from neo4j import Session

from constants import ATTACKER_BUNDLE_ID, ATTACKER_NAME, ALLOW_DYLD_ENTITLEMENT


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


# ── Injection inference rules ───────────────────────────────────────────────
#
# Each rule is a (method, target_match, extra_params) tuple:
#   - method: the string stored on the CAN_INJECT_INTO edge
#   - target_match: Cypher fragment that selects vulnerable targets
#     (appended after the common TCC-grant match + DISTINCT)
#   - extra_params: additional query parameters beyond attacker_id
#
# These rules mirror InjectionAssessment.swift logic:
#   1. missing_library_validation: effectiveLV=false (library_validation prop is pre-computed by collector)
#   2. dyld_insert: hardened_runtime=false → DYLD_INSERT_LIBRARIES
#   3. dyld_insert_via_entitlement: has allow-dyld entitlement
# The Python side limits targets to apps with TCC grants (attack value filter)
# while Swift assesses injection for all apps (collector concern).

_INJECTION_RULES: list[tuple[str, str, dict]] = [
    (
        "missing_library_validation",
        """
        MATCH (target:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        WITH DISTINCT target
        WHERE target.library_validation = false
          AND target.bundle_id <> $attacker_id
          AND NOT coalesce(target.is_sip_protected, false)
        """,
        {},
    ),
    (
        "dyld_insert",
        """
        MATCH (target:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        WITH DISTINCT target
        WHERE target.hardened_runtime = false
          AND target.bundle_id <> $attacker_id
          AND NOT coalesce(target.is_sip_protected, false)
        """,
        {},
    ),
    (
        "dyld_insert_via_entitlement",
        """
        MATCH (target:Application)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        MATCH (target)-[:HAS_ENTITLEMENT]->(:Entitlement {name: $ent})
        WITH DISTINCT target
        WHERE target.bundle_id <> $attacker_id
          AND NOT coalesce(target.is_sip_protected, false)
        """,
        {"ent": ALLOW_DYLD_ENTITLEMENT},
    ),
]


def _run_injection_rule(
    session: Session, method: str, target_match: str, extra_params: dict
) -> int:
    """Run a single injection inference rule. Returns edges created."""
    query = (
        target_match
        + """
        MATCH (attacker:Application {bundle_id: $attacker_id})
        MERGE (attacker)-[r:CAN_INJECT_INTO {method: $method}]->(target)
        SET r.inferred = true,
            r.sandboxed = coalesce(target.is_sandboxed, false)
        RETURN count(r) AS n
        """
    )
    result = session.run(
        query,
        attacker_id=ATTACKER_BUNDLE_ID,
        method=method,
        **extra_params,
    )
    return result.single()["n"]


def infer(session: Session) -> int:
    """
    Infer all CAN_INJECT_INTO relationships. Returns total edge count.
    Idempotent: uses MERGE, safe to re-run.
    """
    ensure_attacker_node(session)
    total = 0
    for method, target_match, extra_params in _INJECTION_RULES:
        total += _run_injection_rule(session, method, target_match, extra_params)
    return total
