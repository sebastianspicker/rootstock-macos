from __future__ import annotations

from unittest import TestCase


from category_predicates import (
    DIVERGENT_RISK_AND_VULNERABILITY_CATEGORIES,
    RISK_CATEGORY_PREDICATES,
    SHARED_CATEGORY_PREDICATES,
    VULNERABILITY_CATEGORY_PREDICATES,
)
from infer_recommendations import _RECOMMENDATIONS
from import_vulnerabilities import _CATEGORY_MATCH


checks = TestCase()


def test_risk_and_vulnerability_consumers_use_declared_category_predicates() -> None:
    checks.assertEqual(_CATEGORY_MATCH, VULNERABILITY_CATEGORY_PREDICATES)
    checks.assertEqual(set(RISK_CATEGORY_PREDICATES), set(_CATEGORY_MATCH))


def test_shared_category_predicates_are_identical_in_current_consumers() -> None:
    for category, predicate in SHARED_CATEGORY_PREDICATES.items():
        checks.assertEqual(
            _normalized(RISK_CATEGORY_PREDICATES[category]), _normalized(predicate)
        )
        checks.assertEqual(
            _normalized(_CATEGORY_MATCH[category]), _normalized(predicate)
        )


def test_divergent_category_predicates_remain_explicitly_separate() -> None:
    checks.assertEqual(
        DIVERGENT_RISK_AND_VULNERABILITY_CATEGORIES,
        {
            "electron_inheritance",
            "esf_bypass",
            "file_acl_escalation",
            "mdm_risk",
            "physical_security",
        },
    )
    for category in DIVERGENT_RISK_AND_VULNERABILITY_CATEGORIES:
        checks.assertNotEqual(
            _normalized(RISK_CATEGORY_PREDICATES[category]),
            _normalized(_CATEGORY_MATCH[category]),
        )


def test_recommendations_reuse_graph_category_predicates_for_shared_conditions() -> (
    None
):
    conditions = {rule.key: rule.condition for rule in _RECOMMENDATIONS}
    expected = {
        "harden_runtime": "injectable_fda",
        "library_validation": "dyld_injection",
        "audit_fda_grants": "injectable_fda",
        "disable_electron_node": "electron_inheritance",
        "sandbox_electron": "electron_inheritance",
        "audit_apple_events": "apple_events",
        "harden_esf_clients": "esf_bypass",
        "patch_sandbox_escapes": "sandbox_escape",
        "review_mdm_pppc": "mdm_risk",
        "audit_file_acls": "file_acl_escalation",
        "monitor_running_injectable": "running_processes",
    }

    for key, category in expected.items():
        checks.assertEqual(
            _normalized(conditions[key]),
            _normalized(RISK_CATEGORY_PREDICATES[category]),
        )


def _normalized(predicate: str) -> str:
    return " ".join(predicate.split())
