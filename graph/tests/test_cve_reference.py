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
    get_all_critical_cves,
    get_context,
    get_contexts_for_query,
    _REGISTRY,
    _VALID_EXPLOITATION_STATUSES,
    _VALID_ATTACK_COMPLEXITIES,
)
from report_formatters import format_vulnerability_summary, _exploitation_icon


_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$")
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_VALID_PRIORITIES = {"Immediate", "High", "Medium"}


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

    def test_at_least_three_actively_exploited(self):
        """Registry should contain at least 3 actively exploited CVEs."""
        exploited = set()
        for ctx in _REGISTRY.values():
            for cve in ctx.cves:
                if getattr(cve, "exploitation_status", "theoretical") == "actively_exploited":
                    exploited.add(cve.cve_id)
        assert len(exploited) >= 3, f"Only {len(exploited)} actively exploited CVEs: {exploited}"

    def test_exploitation_icon_values(self):
        assert _exploitation_icon("actively_exploited") == "[!!!] Active"
        assert _exploitation_icon("poc_available") == "[!!] PoC"
        assert _exploitation_icon("theoretical") == "[!] Theory"
        assert _exploitation_icon("unknown") == ""


# ── New Categories ───────────────────────────────────────────────────────────

_NEW_CATEGORIES = [
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


class TestNewCategories:
    @pytest.mark.parametrize("category", _NEW_CATEGORIES)
    def test_new_category_exists(self, category: str):
        ctx = get_context(category)
        assert ctx is not None, f"Category {category!r} not in registry"
        assert ctx.category == category
        assert len(ctx.techniques) >= 1

    def test_registry_has_at_least_23_categories(self):
        assert len(_REGISTRY) >= 23, f"Only {len(_REGISTRY)} categories in registry"


# ── Expanded Coverage ────────────────────────────────────────────────────────

class TestExpandedCoverage:
    def test_cve_count_at_least_30(self):
        cves = get_all_critical_cves(min_cvss=0.0)
        assert len(cves) >= 30, f"Only {len(cves)} CVEs in registry"

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

    def test_new_cves_reachable_via_get_all_critical(self):
        """New high-CVSS CVEs should appear in the critical list."""
        cves = get_all_critical_cves(min_cvss=8.0)
        cve_ids = {c.cve_id for c in cves}
        # BLASTPASS and Operation Triangulation entries should be present
        assert "CVE-2023-38606" in cve_ids
        assert "CVE-2025-24201" in cve_ids

    def test_technique_count_at_least_25(self):
        """Registry should reference at least 25 unique techniques."""
        techniques = set()
        for ctx in _REGISTRY.values():
            for tech in ctx.techniques:
                techniques.add(tech.technique_id)
        assert len(techniques) >= 25, f"Only {len(techniques)} unique techniques"
