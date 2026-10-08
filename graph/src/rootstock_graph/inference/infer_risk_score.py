"""
infer_risk_score.py - Compute graph-native risk scores on Application and Computer nodes.

Runs last in the inference engine: after all other inference modules and tier
classification, and after vulnerability import (pipeline.sh imports
vulnerabilities before the score stage, so the tier and CVE terms are
populated). Sets per Application:
  - risk_score (float 0.0-10.0)
  - risk_level ("critical" / "high" / "medium" / "low" / "informational")
  - risk_reasons (list[str]): the facts behind the score, in plain language
  - attack_categories (list[str])
  - critical_finding_count, high_finding_count (int)

and, through ``infer_host_posture``, a posture assessment on every Computer node.

The score is the sum of an *exposure* term (how easily an attacker runs code inside
the app) and a *value* term (what that code gains). An app that cannot be injected
keeps only a fraction of its value term, so a hardened app that holds Full Disk
Access ranks below an injectable one with the same grant. Scoring is a pure
Python function over facts fetched in one query, so it is unit-testable and the
written ``risk_reasons`` always agree with the number.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from neo4j import Session

from ..constants import (
    ACCESSIBILITY_SERVICE,
    ATTACKER_BUNDLE_ID,
    ATTACK_CATEGORIES_PROPERTY,
    CRITICAL_FINDING_COUNT_PROPERTY,
    FDA_SERVICE,
    HIGH_FINDING_COUNT_PROPERTY,
    RISK_LEVEL_PROPERTY,
    RISK_REASONS_PROPERTY,
    RISK_SCORE_PROPERTY,
)
from ..category_predicates import RISK_CATEGORY_PREDICATES, RISKY_BROWSER_EXTENSION
from . import infer_host_posture
from .infer_host_posture import risk_level


# Categories that count as critical findings
_CRITICAL_CATEGORIES = {
    "injectable_fda",
    "esf_bypass",
    "persistence_hijack",
    "launchd_env_injection",
}

# Categories that count as high findings
_HIGH_CATEGORIES = {
    "dyld_injection",
    "electron_inheritance",
    "apple_events",
    "accessibility_abuse",
    "keychain_access",
    "xpc_exploitation",
    "sandbox_escape",
}


# ── Scoring weights ──────────────────────────────────────────────────────────

# Exposure: how an attacker gets code into the app. The strongest method counts in
# full; each further method adds a little.
_INJECTION_WEIGHTS = {
    "dyld_insert": 3.0,
    "missing_library_validation": 2.5,
    "dyld_insert_via_entitlement": 2.0,
    "electron_env_var": 2.0,
}
_INJECTION_EXTRA_METHOD = 0.5
_INJECTION_CAP = 3.5
_WEIGHT_UNSIGNED = 1.5
_WEIGHT_ADHOC = 1.0
_WEIGHT_EXPIRED_CERT = 0.5
_WEIGHT_NOT_NOTARIZED = 0.5
_WEIGHT_GATEKEEPER_BYPASS = 0.5
_WEIGHT_ENV_INJECTION = 2.0  # launchd sets DYLD_* for one of the app's jobs
_WEIGHT_RISKY_EXTENSION = 0.5
_RISKY_EXTENSION_CAP = 1.5

# Value: what the attacker gains inside the app.
_WEIGHT_FDA = 2.5
_WEIGHT_CONTROL_GRANT = 1.5  # Accessibility, Screen Recording, Input Monitoring
_WEIGHT_ANY_GRANT = 1.0
_WEIGHT_EXTRA_GRANT = 0.25
_EXTRA_GRANT_CAP = 1.0
_WEIGHT_KEYCHAIN = 1.0
_WEIGHT_ROOT_PERSISTENCE = 1.5
_WEIGHT_PERSISTENCE = 0.5
_WEIGHT_CVE = 1.5
_WEIGHT_KEV = 1.0
_WEIGHT_TIER0 = 1.0
_WEIGHT_RUNNING = 0.5
_WEIGHT_EXPOSED_LISTENER = 1.0
_EXPOSED_LISTENER_CAP = 2.0

# A hardened app still holds its privileges; keep part of the value term.
_UNINJECTABLE_VALUE_FACTOR = 0.4

_CONTROL_SERVICES = {
    ACCESSIBILITY_SERVICE,
    "kTCCServiceScreenCapture",
    "kTCCServiceListenEvent",
    "kTCCServicePostEvent",
}

_SERVICE_NAMES = {
    FDA_SERVICE: "Full Disk Access",
    ACCESSIBILITY_SERVICE: "Accessibility",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServicePostEvent": "Input Monitoring (post events)",
    "kTCCServiceAppleEvents": "Automation",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
}

_INJECTION_REASONS = {
    "dyld_insert": "Hardened Runtime is off, so DYLD_INSERT_LIBRARIES can load code into it",
    "missing_library_validation": "Library Validation is off, so unsigned libraries can be loaded",
    "dyld_insert_via_entitlement": (
        "Holds the allow-dyld-environment-variables entitlement, which re-enables DYLD injection"
    ),
    "electron_env_var": (
        "Electron RunAsNode fuse is enabled, so ELECTRON_RUN_AS_NODE runs attacker code with its permissions"
    ),
}


@dataclass(frozen=True)
class ApplicationFacts:
    """Per-app facts the score is computed from (fetched in one query)."""

    app_key: str
    name: str
    injection_methods: tuple[str, ...] = ()
    signed: bool | None = None
    is_adhoc_signed: bool = False
    is_certificate_expired: bool = False
    is_notarized: bool | None = None
    is_system: bool = False
    is_sip_protected: bool = False
    tier: int | None = None
    is_running: bool = False
    allowed_services: tuple[str, ...] = ()
    keychain_items: int = 0
    root_daemons: int = 0
    persistence_items: int = 0
    cve_ids: tuple[str, ...] = ()
    kev_cve_ids: tuple[str, ...] = ()
    gatekeeper_bypass: bool = False
    electron_inheritance: bool = False
    exposed_listeners: int = 0
    env_injection_items: int = 0
    risky_extensions: int = 0


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    level: str
    reasons: list[str] = field(default_factory=list)


def _exposure(facts: ApplicationFacts) -> tuple[float, list[str]]:
    reasons: list[str] = []
    weights = sorted(
        (_INJECTION_WEIGHTS.get(method, 1.0) for method in facts.injection_methods),
        reverse=True,
    )
    score = 0.0
    if weights:
        score = min(_INJECTION_CAP, weights[0] + _INJECTION_EXTRA_METHOD * (len(weights) - 1))
        for method in facts.injection_methods:
            reasons.append(_INJECTION_REASONS.get(method, f"Injectable via {method}"))
    if facts.signed is False and not facts.is_system:
        score += _WEIGHT_UNSIGNED
        reasons.append("Not code-signed, so its origin and integrity cannot be verified")
    elif facts.is_adhoc_signed and not facts.is_system:
        score += _WEIGHT_ADHOC
        reasons.append("Ad-hoc signature (no developer identity)")
    if facts.is_certificate_expired:
        score += _WEIGHT_EXPIRED_CERT
        reasons.append("Signing certificate has expired")
    if facts.is_notarized is False and not facts.is_system and not facts.is_sip_protected:
        score += _WEIGHT_NOT_NOTARIZED
        reasons.append("Gatekeeper reports the app is not notarized")
    if facts.gatekeeper_bypass:
        score += _WEIGHT_GATEKEEPER_BYPASS
        reasons.append("Installed without a quarantine record, so Gatekeeper never assessed it")
    extra_score, extra_reasons = _persistent_footholds(facts)
    return score + extra_score, reasons + extra_reasons


def _persistent_footholds(facts: ApplicationFacts) -> tuple[float, list[str]]:
    """Code that already runs inside the app without an exploit: launchd DYLD_* and extensions."""
    score = 0.0
    reasons: list[str] = []
    if facts.env_injection_items:
        score += _WEIGHT_ENV_INJECTION
        reasons.append(
            f"{facts.env_injection_items} of its launch item(s) set DYLD_* variables, so launchd "
            "loads a library into it at every start"
        )
    if facts.risky_extensions:
        score += min(_RISKY_EXTENSION_CAP, _WEIGHT_RISKY_EXTENSION * facts.risky_extensions)
        reasons.append(
            f"{facts.risky_extensions} browser extension(s) can read and change every site, "
            "or were installed outside the store"
        )
    return score, reasons


def _grant_value(facts: ApplicationFacts) -> tuple[float, list[str]]:
    services = list(facts.allowed_services)
    if not services:
        return 0.0, []
    reasons: list[str] = []
    if FDA_SERVICE in services:
        score = _WEIGHT_FDA
        reasons.append("Holds Full Disk Access")
    elif any(service in _CONTROL_SERVICES for service in services):
        score = _WEIGHT_CONTROL_GRANT
        names = sorted({_SERVICE_NAMES.get(s, s) for s in services if s in _CONTROL_SERVICES})
        reasons.append(f"Holds {', '.join(names)}")
    else:
        score = _WEIGHT_ANY_GRANT
    extra = len(services) - 1
    if extra > 0:
        score += min(_EXTRA_GRANT_CAP, _WEIGHT_EXTRA_GRANT * extra)
    named = sorted(_SERVICE_NAMES.get(s, s.replace("kTCCService", "")) for s in services)
    reasons.append(f"Allowed privacy permissions: {', '.join(named)}")
    return score, reasons


def _network_value(facts: ApplicationFacts) -> tuple[float, list[str]]:
    """Listening on a non-loopback address makes the app reachable from other machines."""
    if not facts.exposed_listeners:
        return 0.0, []
    score = min(_EXPOSED_LISTENER_CAP, _WEIGHT_EXPOSED_LISTENER * facts.exposed_listeners)
    return score, [
        f"Accepts network connections from other machines on {facts.exposed_listeners} port(s)"
    ]


_CVE_REASON_LIMIT = 5


def _cve_match_reason(cve_ids: tuple[str, ...]) -> str:
    """Name the first few matched CVEs; NVD matches can run into the dozens."""
    ids = sorted(cve_ids)
    shown = ", ".join(ids[:_CVE_REASON_LIMIT])
    if len(ids) > _CVE_REASON_LIMIT:
        shown += f" and {len(ids) - _CVE_REASON_LIMIT} more"
    return f"Installed version matches {len(ids)} published CVE(s): {shown}"


def _value(facts: ApplicationFacts) -> tuple[float, list[str]]:
    score, reasons = _grant_value(facts)
    if facts.keychain_items:
        score += _WEIGHT_KEYCHAIN
        reasons.append(f"Trusted to read {facts.keychain_items} keychain item(s) without a prompt")
    if facts.root_daemons:
        score += _WEIGHT_ROOT_PERSISTENCE
        reasons.append(f"Installs {facts.root_daemons} LaunchDaemon(s) that run as root")
    elif facts.persistence_items:
        score += _WEIGHT_PERSISTENCE
        reasons.append(f"Persists through {facts.persistence_items} launch item(s)")
    if facts.cve_ids:
        score += _WEIGHT_CVE
        reasons.append(_cve_match_reason(facts.cve_ids))
    if facts.kev_cve_ids:
        score += _WEIGHT_KEV
        reasons.append("A matched CVE is in the CISA Known Exploited Vulnerabilities catalog")
    network_score, network_reasons = _network_value(facts)
    score += network_score
    reasons.extend(network_reasons)
    if facts.tier == 0:
        score += _WEIGHT_TIER0
    if facts.is_running:
        score += _WEIGHT_RUNNING
        reasons.append("Was running when the scan was taken")
    return score, reasons


def assess_application(facts: ApplicationFacts) -> RiskAssessment:
    """Pure scoring function: exposure plus value, with the reasons that produced it."""
    exposure, exposure_reasons = _exposure(facts)
    value, value_reasons = _value(facts)
    if exposure > 0:
        raw = exposure + value
    else:
        raw = value * _UNINJECTABLE_VALUE_FACTOR
    score = round(min(10.0, raw), 2)
    return RiskAssessment(
        score=score, level=risk_level(score), reasons=exposure_reasons + value_reasons
    )


# ── Graph I/O ────────────────────────────────────────────────────────────────


def _category_case_clauses() -> str:
    category_cases = []
    for cat, clause in RISK_CATEGORY_PREDICATES.items():
        category_cases.append(f"CASE WHEN {clause} THEN '{cat}' ELSE NULL END")
    return ",\n        ".join(category_cases)


def _set_attack_categories(session: Session) -> None:
    cases_str = _category_case_clauses()
    category_query = f"""
        MATCH (app:Application)
        WHERE app.bundle_id <> $attacker_id
        WITH app,
        [{cases_str}] AS raw_cats
        WITH app, [c IN raw_cats WHERE c IS NOT NULL] AS categories
        SET app.{ATTACK_CATEGORIES_PROPERTY} = categories
        RETURN count(app) AS n
    """
    session.run(category_query, attacker_id=ATTACKER_BUNDLE_ID)


def _set_finding_counts(session: Session) -> None:
    session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{ATTACK_CATEGORIES_PROPERTY} IS NOT NULL
        WITH app,
             size([c IN app.{ATTACK_CATEGORIES_PROPERTY} WHERE c IN $critical_cats]) AS crit,
             size([c IN app.{ATTACK_CATEGORIES_PROPERTY} WHERE c IN $high_cats])
             + CASE WHEN 'network_exposed' IN app.{ATTACK_CATEGORIES_PROPERTY}
                     AND EXISTS {{
                         MATCH (app)-[:LISTENS_ON]->(:NetworkListener {{reachable_without_firewall: true}})
                     }}
                    THEN 1 ELSE 0 END AS high
        SET app.{CRITICAL_FINDING_COUNT_PROPERTY} = crit,
            app.{HIGH_FINDING_COUNT_PROPERTY} = high
        """,
        critical_cats=sorted(_CRITICAL_CATEGORIES),
        high_cats=sorted(_HIGH_CATEGORIES),
    )


_APPLICATION_FACTS_QUERY = (
    """
    MATCH (app:Application)
    WHERE app.bundle_id <> $attacker_id
    OPTIONAL MATCH (app)-[g:HAS_TCC_GRANT {allowed: true}]->(perm:TCC_Permission)
    WITH app, collect(DISTINCT perm.service) AS services
    OPTIONAL MATCH (app)-[:CAN_READ_KEYCHAIN]->(k:Keychain_Item)
    WITH app, services, count(DISTINCT k) AS keychain_items
    OPTIONAL MATCH (app)-[:PERSISTS_VIA]->(li:LaunchItem)
    OPTIONAL MATCH (li)-[:RUNS_AS]->(u:User)
    WITH app, services, keychain_items,
         count(DISTINCT li) AS persistence_items,
         count(DISTINCT CASE WHEN li.type = 'daemon' AND coalesce(u.name, 'root') = 'root' THEN li END) AS root_daemons
    OPTIONAL MATCH (app)-[:AFFECTED_BY]->(v:Vulnerability)
    WITH app, services, keychain_items, persistence_items, root_daemons,
         collect(DISTINCT v.cve_id) AS cve_ids,
         collect(DISTINCT CASE WHEN v.in_kev THEN v.cve_id END) AS kev_cve_ids
    RETURN app.app_key AS app_key,
           app.name AS name,
           coalesce(app.injection_methods, []) AS injection_methods,
           app.signed AS signed,
           coalesce(app.is_adhoc_signed, false) AS is_adhoc_signed,
           coalesce(app.is_certificate_expired, false) AS is_certificate_expired,
           app.is_notarized AS is_notarized,
           coalesce(app.is_system, false) AS is_system,
           coalesce(app.is_sip_protected, false) AS is_sip_protected,
           app.tier AS tier,
           coalesce(app.is_running, false) AS is_running,
           services,
           keychain_items,
           root_daemons,
           persistence_items,
           cve_ids,
           [c IN kev_cve_ids WHERE c IS NOT NULL] AS kev_cve_ids,
           EXISTS { MATCH ()-[:BYPASSED_GATEKEEPER]->(app) } AS gatekeeper_bypass,
           EXISTS { MATCH ()-[:CHILD_INHERITS_TCC]->(app) } AS electron_inheritance,
           COUNT { MATCH (app)-[:LISTENS_ON]->(nl:NetworkListener) WHERE nl.exposed = true }
               AS exposed_listeners,
           COUNT {
               MATCH (app)-[:PERSISTS_VIA]->(eli:LaunchItem)
               WHERE eli.launchd_dyld_injection = true
           } AS env_injection_items,
           COUNT {
               MATCH (app)-[:HAS_EXTENSION]->(be:BrowserExtension)
               WHERE """
    + RISKY_BROWSER_EXTENSION
    + """
           } AS risky_extensions
"""
)


def _facts_from_record(record) -> ApplicationFacts:
    return ApplicationFacts(
        app_key=record["app_key"],
        name=record["name"] or "",
        injection_methods=tuple(record["injection_methods"] or ()),
        signed=record["signed"],
        is_adhoc_signed=bool(record["is_adhoc_signed"]),
        is_certificate_expired=bool(record["is_certificate_expired"]),
        is_notarized=record["is_notarized"],
        is_system=bool(record["is_system"]),
        is_sip_protected=bool(record["is_sip_protected"]),
        tier=record["tier"],
        is_running=bool(record["is_running"]),
        allowed_services=tuple(record["services"] or ()),
        keychain_items=int(record["keychain_items"] or 0),
        root_daemons=int(record["root_daemons"] or 0),
        persistence_items=int(record["persistence_items"] or 0),
        cve_ids=tuple(record["cve_ids"] or ()),
        kev_cve_ids=tuple(record["kev_cve_ids"] or ()),
        gatekeeper_bypass=bool(record["gatekeeper_bypass"]),
        electron_inheritance=bool(record["electron_inheritance"]),
        exposed_listeners=int(record["exposed_listeners"] or 0),
        env_injection_items=int(record["env_injection_items"] or 0),
        risky_extensions=int(record["risky_extensions"] or 0),
    )


def _set_risk_scores(session: Session) -> int:
    records = list(session.run(_APPLICATION_FACTS_QUERY, attacker_id=ATTACKER_BUNDLE_ID))
    rows = []
    for record in records:
        facts = _facts_from_record(record)
        if not facts.app_key:
            continue
        assessment = assess_application(facts)
        rows.append(
            {
                "app_key": facts.app_key,
                "score": assessment.score,
                "level": assessment.level,
                "reasons": assessment.reasons,
            }
        )
    if not rows:
        return 0
    session.run(
        f"""
        UNWIND $rows AS row
        MATCH (app:Application {{app_key: row.app_key}})
        SET app.{RISK_SCORE_PROPERTY} = row.score,
            app.{RISK_LEVEL_PROPERTY} = row.level,
            app.{RISK_REASONS_PROPERTY} = row.reasons
        """,
        rows=rows,
    )
    return len(rows)


def infer(session: Session) -> int:
    """
    Compute risk scores, reasons and attack categories for all Application nodes
    and a posture assessment for every Computer node.

    Returns the number of Application nodes scored.
    """
    _set_attack_categories(session)
    _set_finding_counts(session)
    scored = _set_risk_scores(session)
    infer_host_posture.infer(session)
    return scored
