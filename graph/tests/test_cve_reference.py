"""
test_cve_reference.py — Tests for the CVE & ATT&CK reference registry.

Pure unit tests — no Neo4j required.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

# Ensure graph/ is on sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cve_reference import (
    AttackContext,
    CveEntry,
    CWE_REGISTRY,
    get_all_critical_cves,
    get_cwe,
    get_context,
    get_contexts_for_query,
    _REGISTRY,
    _VALID_EXPLOITATION_STATUSES,
    _VALID_ATTACK_COMPLEXITIES,
)
from report_formatters import format_vulnerability_summary, _exploitation_icon


_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$")
_CWE_ID_RE = re.compile(r"^CWE-\d+$")
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_VALID_PRIORITIES = {"Immediate", "High", "Medium"}
_REQUIRED_CATEGORY_CVES = {
    "injectable_fda": {"CVE-2025-31191", "CVE-2024-44168"},
    "kernel_escalation": {"CVE-2025-24085", "CVE-2025-24118"},
    "blastpass_class": {"CVE-2023-41064", "CVE-2023-41061"},
    "sandbox_escape": {"CVE-2023-38606"},
    "gatekeeper_bypass": {"CVE-2022-42821", "CVE-2024-44175"},
    "running_processes": {"CVE-2025-24201"},
}


def _registry_cves() -> list[CveEntry]:
    return [cve for ctx in _REGISTRY.values() for cve in ctx.cves]


def _unique_cves_by_id() -> dict[str, CveEntry]:
    unique: dict[str, CveEntry] = {}
    for cve in _registry_cves():
        unique.setdefault(cve.cve_id, cve)
    return unique


# ── Registry integrity ───────────────────────────────────────────────────────

class TestRegistryIntegrity:
    def test_all_categories_have_at_least_one_technique(self):
        missing = []
        for cat, ctx in _REGISTRY.items():
            if not ctx.techniques:
                missing.append(cat)
        assert not missing, f"Categories without techniques: {missing}"

    def test_cve_ids_match_format(self):
        bad = []
        for ctx in _REGISTRY.values():
            for cve in ctx.cves:
                if not _CVE_ID_RE.match(cve.cve_id):
                    bad.append(cve.cve_id)
        assert not bad, f"Invalid CVE ID format: {bad}"

    def test_technique_ids_match_format(self):
        bad = []
        for ctx in _REGISTRY.values():
            for tech in ctx.techniques:
                if not _TECHNIQUE_ID_RE.match(tech.technique_id):
                    bad.append(tech.technique_id)
        assert not bad, f"Invalid technique ID format: {bad}"

    def test_cvss_scores_in_range(self):
        out_of_range = []
        for ctx in _REGISTRY.values():
            for cve in ctx.cves:
                if not (0.0 <= cve.cvss_score <= 10.0):
                    out_of_range.append(f"{cve.cve_id}: {cve.cvss_score}")
        assert not out_of_range, f"CVSS scores out of range: {out_of_range}"

    def test_remediation_priorities_valid(self):
        bad = []
        for cat, ctx in _REGISTRY.items():
            if ctx.remediation_priority not in _VALID_PRIORITIES:
                bad.append(f"{cat}: {ctx.remediation_priority}")
        assert not bad, f"Invalid priorities: {bad}"

    def test_category_field_matches_key(self):
        mismatched = []
        for key, ctx in _REGISTRY.items():
            if ctx.category != key:
                mismatched.append(f"{key} != {ctx.category}")
        assert not mismatched, f"Category/key mismatch: {mismatched}"

    def test_no_duplicate_cve_ids_within_category(self):
        duplicates = []
        for category, ctx in _REGISTRY.items():
            cve_ids = [cve.cve_id for cve in ctx.cves]
            duplicate_ids = sorted({cve_id for cve_id in cve_ids if cve_ids.count(cve_id) > 1})
            if duplicate_ids:
                duplicates.append(f"{category}: {duplicate_ids}")
        assert not duplicates, f"Duplicate CVE IDs in category: {duplicates}"

    def test_duplicate_cve_ids_have_identical_records(self):
        """CVEs may be referenced by multiple categories, but must not conflict."""
        seen: dict[str, CveEntry] = {}
        conflicts = []
        for cve in _registry_cves():
            existing = seen.setdefault(cve.cve_id, cve)
            if existing != cve:
                conflicts.append(cve.cve_id)
        assert not conflicts, f"Conflicting duplicate CVE records: {sorted(conflicts)}"

    def test_cve_required_fields_populated(self):
        missing = []
        for cve in _unique_cves_by_id().values():
            required = {
                "title": cve.title,
                "affected_versions": cve.affected_versions,
                "description": cve.description,
                "reference_url": cve.reference_url,
            }
            for field, value in required.items():
                if not value.strip():
                    missing.append(f"{cve.cve_id}.{field}")
            if cve.patched_version is not None and not cve.patched_version.strip():
                missing.append(f"{cve.cve_id}.patched_version")
            if not cve.cwe_ids:
                missing.append(f"{cve.cve_id}.cwe_ids")
            if not cve.reference_url.startswith(("https://", "http://")):
                missing.append(f"{cve.cve_id}.reference_url")
        assert not missing, f"Missing or invalid CVE fields: {missing}"

    def test_referenced_cwe_ids_resolve(self):
        unresolved = []
        for cve in _unique_cves_by_id().values():
            for cwe_id in cve.cwe_ids:
                cwe = get_cwe(cwe_id)
                if not _CWE_ID_RE.match(cwe_id) or cwe is None:
                    unresolved.append(f"{cve.cve_id}: {cwe_id}")
        assert not unresolved, f"Unresolved CWE references: {unresolved}"

    def test_cwe_registry_entries_are_populated(self):
        bad = []
        for cwe_id, cwe in CWE_REGISTRY.items():
            if cwe_id != cwe.cwe_id or not _CWE_ID_RE.match(cwe.cwe_id):
                bad.append(f"{cwe_id}: id mismatch")
            if not cwe.name.strip():
                bad.append(f"{cwe_id}: missing name")
            if not cwe.category.strip():
                bad.append(f"{cwe_id}: missing category")
        assert not bad, f"Invalid CWE registry entries: {bad}"


# ── Public API ────────────────────────────────────────────────────────────────

class TestGetContext:
    def test_known_category_returns_context(self):
        ctx = get_context("injectable_fda")
        assert ctx is not None
        assert isinstance(ctx, AttackContext)
        assert ctx.category == "injectable_fda"

    def test_unknown_category_returns_none(self):
        assert get_context("nonexistent_category") is None

    def test_injectable_fda_has_expected_cves(self):
        ctx = get_context("injectable_fda")
        assert ctx is not None
        cve_ids = {c.cve_id for c in ctx.cves}
        assert "CVE-2025-31191" in cve_ids
        assert "CVE-2024-44168" in cve_ids

    def test_authorization_hardening_has_no_cves(self):
        ctx = get_context("authorization_hardening")
        assert ctx is not None
        assert ctx.cves == []
        assert len(ctx.techniques) >= 1


class TestGetContextsForQuery:
    def test_query_with_cve_field(self):
        query = {"cve": "CVE-2025-31191, CVE-2024-44168"}
        contexts = get_contexts_for_query(query)
        assert len(contexts) >= 1
        categories = {c.category for c in contexts}
        assert "injectable_fda" in categories

    def test_query_without_cve_field(self):
        query = {"name": "Some query", "cve": ""}
        assert get_contexts_for_query(query) == []

    def test_query_missing_cve_key(self):
        query = {"name": "Some query"}
        assert get_contexts_for_query(query) == []


class TestGetAllCriticalCves:
    def test_returns_high_cvss_entries(self):
        cves = get_all_critical_cves(min_cvss=8.0)
        assert len(cves) >= 1
        for cve in cves:
            assert cve.cvss_score >= 8.0

    def test_sorted_by_cvss_descending(self):
        cves = get_all_critical_cves(min_cvss=0.0)
        for i in range(len(cves) - 1):
            assert cves[i].cvss_score >= cves[i + 1].cvss_score

    def test_no_duplicates(self):
        cves = get_all_critical_cves(min_cvss=0.0)
        ids = [c.cve_id for c in cves]
        assert len(ids) == len(set(ids)), "Duplicate CVE IDs in results"

    def test_high_threshold_filters_correctly(self):
        cves_high = get_all_critical_cves(min_cvss=9.0)
        cves_all = get_all_critical_cves(min_cvss=0.0)
        assert len(cves_high) < len(cves_all)


# ── Formatter ─────────────────────────────────────────────────────────────────

class TestFormatVulnerabilitySummary:
    def test_empty_contexts_returns_fallback(self):
        result = format_vulnerability_summary([])
        assert "No CVE" in result

    def test_single_context_produces_tables(self):
        ctx = get_context("injectable_fda")
        assert ctx is not None
        result = format_vulnerability_summary([ctx])
        assert "CVE-2025-31191" in result
        assert "T1574.006" in result
        assert "### CVE Reference" in result
        assert "### MITRE ATT&CK Techniques" in result

    def test_deduplication_across_categories(self):
        ctx1 = get_context("injectable_fda")
        ctx2 = get_context("dyld_injection")
        assert ctx1 is not None and ctx2 is not None
        result = format_vulnerability_summary([ctx1, ctx2])
        # CVE-2025-31191 appears in both categories but should appear once in table
        assert result.count("CVE-2025-31191") == 1

    def test_category_without_cves_still_shows_techniques(self):
        ctx = get_context("authorization_hardening")
        assert ctx is not None
        result = format_vulnerability_summary([ctx])
        assert "T1548.003" in result

    def test_multiple_categories_produce_valid_markdown(self):
        contexts = [
            get_context("injectable_fda"),
            get_context("electron_inheritance"),
            get_context("apple_events"),
        ]
        contexts = [c for c in contexts if c is not None]
        result = format_vulnerability_summary(contexts)
        # Check table headers present
        assert "CVE ID" in result
        assert "CVSS" in result
        assert "Technique" in result
        # Check pipe-delimited table format (github tablefmt)
        assert "|" in result


# ── Exploitation Status ──────────────────────────────────────────────────────

class TestExploitationStatus:
    def test_all_statuses_are_valid(self):
        """Every CVE in the registry has a valid exploitation_status."""
        bad = []
        for ctx in _REGISTRY.values():
            for cve in ctx.cves:
                status = getattr(cve, "exploitation_status", "theoretical")
                if status not in _VALID_EXPLOITATION_STATUSES:
                    bad.append(f"{cve.cve_id}: {status}")
        assert not bad, f"Invalid exploitation statuses: {bad}"

    def test_all_complexities_are_valid(self):
        """Every CVE in the registry has a valid attack_complexity."""
        bad = []
        for ctx in _REGISTRY.values():
            for cve in ctx.cves:
                complexity = getattr(cve, "attack_complexity", "medium")
                if complexity not in _VALID_ATTACK_COMPLEXITIES:
                    bad.append(f"{cve.cve_id}: {complexity}")
        assert not bad, f"Invalid attack complexities: {bad}"

    def test_exploitation_icon_values(self):
        assert _exploitation_icon("actively_exploited") == "[!!!] Active"
        assert _exploitation_icon("poc_available") == "[!!] PoC"
        assert _exploitation_icon("theoretical") == "[!] Theory"
        assert _exploitation_icon("unknown") == ""


# ── Regression Categories ────────────────────────────────────────────────────

_REGRESSION_CATEGORIES = [
    "certificate_hygiene",
    "shell_hooks",
    "file_acl_escalation",
    "esf_bypass",
    "sandbox_escape",
    "mdm_risk",
    "lateral_movement",
    "running_processes",
    "auth_plugin_risk",
    "blastpass_class",
    "firewall_exposure",
]


class TestRegressionCategories:
    @pytest.mark.parametrize("category", _REGRESSION_CATEGORIES)
    def test_regression_category_exists(self, category: str):
        ctx = get_context(category)
        assert ctx is not None, f"Category {category!r} not in registry"
        assert ctx.category == category
        assert len(ctx.techniques) >= 1

    @pytest.mark.parametrize("category, expected_cves", _REQUIRED_CATEGORY_CVES.items())
    def test_known_category_cves_remain_reachable(
        self,
        category: str,
        expected_cves: set[str],
    ):
        ctx = get_context(category)
        assert ctx is not None, f"Category {category!r} not in registry"
        actual = {cve.cve_id for cve in ctx.cves}
        assert expected_cves <= actual


# ── Regression Coverage ──────────────────────────────────────────────────────

class TestRegressionCoverage:
    def test_known_cves_reachable_via_unique_registry(self):
        cves = _unique_cves_by_id()
        expected = set().union(*_REQUIRED_CATEGORY_CVES.values())
        missing = sorted(expected - set(cves))
        assert not missing, f"Known regression CVEs missing: {missing}"

    def test_formatter_shows_exploited_column(self):
        ctx = get_context("kernel_escalation")
        assert ctx is not None
        result = format_vulnerability_summary([ctx])
        assert "Exploited" in result

    def test_actively_exploited_shows_triple_bang(self):
        ctx = get_context("kernel_escalation")
        assert ctx is not None
        result = format_vulnerability_summary([ctx])
        assert "!!!" in result

    def test_poc_available_shows_double_bang(self):
        ctx = get_context("file_acl_escalation")
        assert ctx is not None
        result = format_vulnerability_summary([ctx])
        assert "!!" in result

    def test_regression_cves_reachable_via_get_all_critical(self):
        """High-CVSS regression CVEs should appear in the critical list."""
        cves = get_all_critical_cves(min_cvss=8.0)
        cve_ids = {c.cve_id for c in cves}
        assert "CVE-2023-38606" in cve_ids
        assert "CVE-2025-24201" in cve_ids
