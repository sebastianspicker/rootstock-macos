"""
infer_risk_score.py - Compute graph-native risk scores on Application nodes.

Runs after all other inference + tier classification to set per-node:
  - risk_score (float 0.0-10.0)
  - risk_level ("critical" / "high" / "medium" / "low")
  - attack_categories (list[str])
  - critical_finding_count, high_finding_count (int)

This makes risk data queryable via Cypher and visible in the viewer/API
without recomputing in Python at report time.
"""

from __future__ import annotations

from neo4j import Session

from constants import (
    RISK_SCORE_PROPERTY,
    RISK_LEVEL_PROPERTY,
    ATTACK_CATEGORIES_PROPERTY,
    CRITICAL_FINDING_COUNT_PROPERTY,
    HIGH_FINDING_COUNT_PROPERTY,
)
from category_predicates import RISK_CATEGORY_PREDICATES


# Categories that count as critical findings
_CRITICAL_CATEGORIES = {
    "injectable_fda",
    "esf_bypass",
}

# Categories that count as high findings
_HIGH_CATEGORIES = {
    "dyld_injection",
    "electron_inheritance",
    "apple_events",
    "accessibility_abuse",
    "keychain_access",
    "xpc_exploitation",
}


# ── Scoring weights ──────────────────────────────────────────────────────────

_WEIGHT_INJECTION = 3.0  # Has injection methods
_WEIGHT_FDA = 2.0  # Has FDA grant
_WEIGHT_TCC = 1.0  # Has any TCC grant
_WEIGHT_TIER0 = 1.5  # Tier 0 classification
_WEIGHT_CVE = 1.5  # Has CVE exposure
_WEIGHT_CERT_ISSUE = 0.5  # Certificate health issue
_WEIGHT_ELECTRON = 1.0  # Electron TCC inheritance


def _category_case_clauses() -> str:
    category_cases = []
    for cat, clause in RISK_CATEGORY_PREDICATES.items():
        category_cases.append(f"CASE WHEN {clause} THEN '{cat}' ELSE NULL END")
    return ",\n        ".join(category_cases)


def _set_attack_categories(session: Session) -> None:
    cases_str = _category_case_clauses()
    category_query = f"""
        MATCH (app:Application)
        WITH app,
        [{cases_str}] AS raw_cats
        WITH app, [c IN raw_cats WHERE c IS NOT NULL] AS categories
        SET app.{ATTACK_CATEGORIES_PROPERTY} = categories
        RETURN count(app) AS n
    """
    session.run(category_query)


def _set_finding_counts(session: Session) -> None:
    critical_cats = list(_CRITICAL_CATEGORIES)
    high_cats = list(_HIGH_CATEGORIES)

    session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{ATTACK_CATEGORIES_PROPERTY} IS NOT NULL
        WITH app,
             size([c IN app.{ATTACK_CATEGORIES_PROPERTY} WHERE c IN $critical_cats]) AS crit,
             size([c IN app.{ATTACK_CATEGORIES_PROPERTY} WHERE c IN $high_cats]) AS high
        SET app.{CRITICAL_FINDING_COUNT_PROPERTY} = crit,
            app.{HIGH_FINDING_COUNT_PROPERTY} = high
        """,
        critical_cats=critical_cats,
        high_cats=high_cats,
    )


def _set_risk_scores(session: Session) -> None:
    session.run(
        f"""
        MATCH (app:Application)
        WITH app,
             EXISTS {{
                 MATCH (app)-[:HAS_TCC_GRANT {{allowed: true}}]->(:TCC_Permission {{service: 'kTCCServiceSystemPolicyAllFiles'}})
             }} AS has_fda,
             EXISTS {{
                 MATCH (app)-[:HAS_TCC_GRANT {{allowed: true}}]->(:TCC_Permission)
             }} AS has_tcc,
             EXISTS {{
                 MATCH (app)-[:AFFECTED_BY]->(:Vulnerability)
             }} AS has_cve
        WITH app,
             CASE WHEN coalesce(size(app.injection_methods), 0) > 0 THEN $w_inj ELSE 0.0 END +
             CASE WHEN has_fda THEN $w_fda ELSE 0.0 END +
             CASE WHEN has_tcc AND NOT has_fda THEN $w_tcc ELSE 0.0 END +
             CASE WHEN app.tier = 0 THEN $w_tier ELSE 0.0 END +
             CASE WHEN has_cve THEN $w_cve ELSE 0.0 END +
             CASE WHEN coalesce(app.is_certificate_expired, false) = true
                  OR coalesce(app.is_adhoc_signed, false) = true
                  THEN $w_cert ELSE 0.0 END +
             CASE WHEN EXISTS {{
                 MATCH ()-[:CHILD_INHERITS_TCC]->(app)
             }} THEN $w_elec ELSE 0.0 END
             AS raw_score
        SET app.{RISK_SCORE_PROPERTY} = CASE
                WHEN raw_score > 10.0 THEN 10.0
                ELSE round(raw_score * 100) / 100.0
            END,
            app.{RISK_LEVEL_PROPERTY} = CASE
                WHEN raw_score >= 7.0 THEN 'critical'
                WHEN raw_score >= 5.0 THEN 'high'
                WHEN raw_score >= 3.0 THEN 'medium'
                ELSE 'low'
            END
        """,
        w_inj=_WEIGHT_INJECTION,
        w_fda=_WEIGHT_FDA,
        w_tcc=_WEIGHT_TCC,
        w_tier=_WEIGHT_TIER0,
        w_cve=_WEIGHT_CVE,
        w_cert=_WEIGHT_CERT_ISSUE,
        w_elec=_WEIGHT_ELECTRON,
    )


def _count_scored_apps(session: Session) -> int:
    scored = session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{RISK_SCORE_PROPERTY} IS NOT NULL
        RETURN count(app) AS n
        """
    )
    return scored.single()["n"]


def infer(session: Session) -> int:
    """
    Compute risk scores and attack categories for all Application nodes.

    Returns the number of Application nodes updated.
    """
    _set_attack_categories(session)
    _set_finding_counts(session)
    _set_risk_scores(session)
    return _count_scored_apps(session)
