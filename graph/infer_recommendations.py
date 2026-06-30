"""
infer_recommendations.py — Create graph-native Recommendation nodes with edges.

Creates (:Recommendation) nodes and links them to Application nodes via
(:Application)-[:HAS_RECOMMENDATION]->(:Recommendation) edges based on
the same conditions as report_assembly.py RECOMMENDATIONS.

Also creates (:Recommendation)-[:MITIGATES]->(:AttackTechnique) edges
for recommendations that map to ATT&CK techniques.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, cast

from neo4j import Session
from neo4j.exceptions import Neo4jError

from category_predicates import RISK_CATEGORY_PREDICATES

logger = logging.getLogger(__name__)


# ── Recommendation definitions ───────────────────────────────────────────────


@dataclass(frozen=True)
class RecommendationRule:
    key: str
    category: str
    text: str
    priority: str
    technique_ids: tuple[str, ...]
    condition: str


_HAS_RECOMMENDATION_TEMPLATE = """
    MATCH (app:Application)
    WHERE {condition}
    MATCH (r:Recommendation {{key: $key}})
    MERGE (app)-[:HAS_RECOMMENDATION]->(r)
    RETURN count(*) AS n
"""


_RECOMMENDATIONS: list[RecommendationRule] = [
    RecommendationRule(
        "harden_runtime",
        "injectable_fda",
        "Enable Hardened Runtime for all first-party and in-house applications.",
        "critical",
        ("T1574.006",),
        RISK_CATEGORY_PREDICATES["injectable_fda"],
    ),
    RecommendationRule(
        "library_validation",
        "injectable_fda",
        "Enable Library Validation to prevent unsigned dylib injection.",
        "critical",
        ("T1574.006",),
        RISK_CATEGORY_PREDICATES["dyld_injection"],
    ),
    RecommendationRule(
        "audit_fda_grants",
        "injectable_fda",
        "Audit all applications with Full Disk Access — revoke unnecessary grants.",
        "critical",
        (),
        RISK_CATEGORY_PREDICATES["injectable_fda"],
    ),
    RecommendationRule(
        "disable_electron_node",
        "electron_inheritance",
        "Disable ELECTRON_RUN_AS_NODE support in production Electron builds.",
        "high",
        ("T1574.006", "T1059.007"),
        RISK_CATEGORY_PREDICATES["electron_inheritance"],
    ),
    RecommendationRule(
        "sandbox_electron",
        "electron_inheritance",
        "Sandbox Electron apps using macOS App Sandbox to limit blast radius.",
        "high",
        (),
        RISK_CATEGORY_PREDICATES["electron_inheritance"],
    ),
    RecommendationRule(
        "audit_apple_events",
        "apple_events",
        "Audit Apple Event automation grants — revoke kTCCServiceAppleEvents from low-trust apps.",
        "high",
        ("T1059.002",),
        RISK_CATEGORY_PREDICATES["apple_events"],
    ),
    RecommendationRule(
        "enable_lockdown_mode",
        "physical_security",
        "Enable Lockdown Mode on high-value targets to reduce zero-click attack surface.",
        "medium",
        ("T1200",),
        """false""",
    ),
    RecommendationRule(
        "require_notarization",
        "certificate_hygiene",
        "Require notarization for all in-house applications before deployment.",
        "high",
        ("T1553.001",),
        """app.signed = true AND (
            coalesce(app.is_certificate_expired, false) = true
            OR coalesce(app.is_adhoc_signed, false) = true
        )""",
    ),
    RecommendationRule(
        "audit_shell_hooks",
        "shell_hooks",
        "Audit writable shell configuration files — restrict write access to owning user.",
        "high",
        ("T1546.004",),
        """size(app.injection_methods) > 0
        AND EXISTS { MATCH (app)-[:PERSISTS_VIA]->(:LaunchItem)-[:RUNS_AS]->(u:User)-[:CAN_INJECT_SHELL]->(:CriticalFile) }""",
    ),
    RecommendationRule(
        "harden_esf_clients",
        "esf_bypass",
        "Harden injectable apps with ESF entitlements — these can blind EDR monitoring.",
        "critical",
        ("T1014", "T1562.001"),
        RISK_CATEGORY_PREDICATES["esf_bypass"],
    ),
    RecommendationRule(
        "patch_sandbox_escapes",
        "sandbox_escape",
        "Prioritise patching sandbox escape CVEs — sandbox escapes enable full system access.",
        "critical",
        ("T1612",),
        RISK_CATEGORY_PREDICATES["sandbox_escape"],
    ),
    RecommendationRule(
        "review_mdm_pppc",
        "mdm_risk",
        "Review MDM PPPC profiles for overgrants to scripting interpreters.",
        "high",
        ("T1548.004",),
        RISK_CATEGORY_PREDICATES["mdm_risk"],
    ),
    RecommendationRule(
        "restrict_remote_access",
        "lateral_movement",
        "Restrict SSH and Screen Sharing access to authorised users via MDM.",
        "high",
        ("T1021.004", "T1021.005"),
        """EXISTS {
            MATCH (app)-[:INSTALLED_ON]->(:Computer)<-[:LOCAL_TO]-(u:User)
            MATCH (:RemoteAccessService {enabled: true})-[:ACCESSIBLE_BY]->(u)
        }""",
    ),
    RecommendationRule(
        "audit_file_acls",
        "file_acl_escalation",
        "Audit file ACLs on security-critical files — remove non-root write ACEs.",
        "high",
        ("T1098",),
        RISK_CATEGORY_PREDICATES["file_acl_escalation"],
    ),
    RecommendationRule(
        "audit_sudoers",
        "authorization_hardening",
        "Audit sudoers NOPASSWD entries — remove unnecessary passwordless sudo rules.",
        "medium",
        ("T1548.003",),
        """EXISTS {
            MATCH (app)-[:INSTALLED_ON]->(:Computer)<-[:LOCAL_TO]-(:User)-[:SUDO_NOPASSWD]->(:SudoersRule)
        }""",
    ),
    RecommendationRule(
        "gatekeeper_enforcement",
        "gatekeeper_bypass",
        "Investigate unquarantined non-system applications that bypassed Gatekeeper.",
        "high",
        ("T1553.001",),
        """EXISTS { MATCH ()-[:BYPASSED_GATEKEEPER]->(app) }""",
    ),
    RecommendationRule(
        "monitor_running_injectable",
        "running_processes",
        "Monitor running injectable processes with active TCC grants.",
        "high",
        ("T1574.006",),
        RISK_CATEGORY_PREDICATES["running_processes"],
    ),
]


def infer(session: Session) -> int:
    """
    Create Recommendation nodes and HAS_RECOMMENDATION + MITIGATES edges.

    Returns the total number of HAS_RECOMMENDATION edges created.
    """
    total_edges = 0
    edge_failures: list[str] = []

    for rule in _RECOMMENDATIONS:
        _merge_recommendation_node(session, rule)
        _link_recommendation_techniques(session, rule)

    for rule in _RECOMMENDATIONS:
        try:
            total_edges += _create_recommendation_edges(session, rule)
        except Neo4jError as exc:
            edge_failures.append(f"{rule.key}: {exc}")
            logger.error(
                "Recommendation edge creation failed for key=%s: %s",
                rule.key,
                exc,
            )

    if edge_failures:
        raise RuntimeError(
            "Recommendation edge creation failed: " + "; ".join(edge_failures)
        )
    return total_edges


def _merge_recommendation_node(session: Session, rule: RecommendationRule) -> None:
    session.run(
        """
        MERGE (r:Recommendation {key: $key})
        SET r.category = $category,
            r.text     = $text,
            r.priority = $priority
        """,
        key=rule.key,
        category=rule.category,
        text=rule.text,
        priority=rule.priority,
    )


def _link_recommendation_techniques(
    session: Session,
    rule: RecommendationRule,
) -> None:
    for tid in rule.technique_ids:
        session.run(
            """
            MATCH (r:Recommendation {key: $key})
            MATCH (t:AttackTechnique {technique_id: $tid})
            MERGE (r)-[:MITIGATES]->(t)
            """,
            key=rule.key,
            tid=tid,
        )


def _create_recommendation_edges(
    session: Session,
    rule: RecommendationRule,
) -> int:
    cypher = _HAS_RECOMMENDATION_TEMPLATE.format(condition=rule.condition)
    result = session.run(cast(Any, cypher), key=rule.key)
    record = result.single()
    return int(record["n"]) if record else 0
