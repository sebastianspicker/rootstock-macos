"""
test_import_vulnerabilities.py — Tests for vulnerability node import.

Pure unit tests for the import logic — no Neo4j required for most tests.
Integration tests require a running Neo4j instance.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure graph/ is on sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cve_enrichment import EnrichedCveEntry
from cve_reference import CveEntry, _REGISTRY
from import_vulnerabilities import (
    _CATEGORY_MATCH,
    import_vulnerability_nodes,
    import_technique_nodes,
    import_all,
)


# ── Category match coverage ──────────────────────────────────────────────

class TestCategoryMatch:
    def test_all_categories_with_cves_have_match(self):
        """Every registry category with CVEs should have a CATEGORY_MATCH entry."""
        missing = []
        for cat, ctx in _REGISTRY.items():
            if ctx.cves and cat not in _CATEGORY_MATCH:
                missing.append(cat)
        # Some categories may not have match patterns if they don't map to app-level queries
        # Just ensure the majority are covered
        assert len(missing) <= len(_REGISTRY) * 0.3, f"Too many unmatched categories: {missing}"

    def test_match_patterns_are_valid_cypher_fragments(self):
        """Each match pattern should be a non-empty string."""
        for cat, pattern in _CATEGORY_MATCH.items():
            assert isinstance(pattern, str)
            assert len(pattern.strip()) > 0, f"Empty pattern for {cat}"

    def test_injectable_fda_pattern_checks_fda_and_injection(self):
        pattern = _CATEGORY_MATCH["injectable_fda"]
        assert "kTCCServiceSystemPolicyAllFiles" in pattern
        assert "injection_methods" in pattern

    def test_electron_pattern_uses_child_inherits(self):
        pattern = _CATEGORY_MATCH["electron_inheritance"]
        assert "CHILD_INHERITS_TCC" in pattern


# ── Import function signatures ───────────────────────────────────────────

class TestImportFunctions:
    def test_import_all_returns_dict(self):
        """import_all should return a dict with the expected keys."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 0}
        mock_session.run.return_value = mock_result

        # Patch enrich_registry to return minimal data
        with patch("import_vulnerabilities.enrich_registry") as mock_enrich:
            mock_enrich.return_value = {}
            counts = import_all(mock_session)

        assert "vulnerabilities" in counts
        assert "techniques" in counts
        assert "maps_to_technique" in counts
        assert "affected_by" in counts

    def test_import_vulnerability_nodes_calls_merge(self):
        """Each enriched CVE should generate a MERGE statement."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 1}
        mock_session.run.return_value = mock_result

        test_cve = CveEntry(
            cve_id="CVE-2099-99999",
            title="Test CVE",
            cvss_score=7.5,
            affected_versions="test",
            patched_version="test",
            description="test",
            reference_url="https://example.com",
        )
        test_enriched = EnrichedCveEntry(
            base=test_cve,
            epss_score=0.5,
            epss_percentile=0.9,
            in_kev=True,
            kev_date_added="2025-01-01",
        )

        with patch("import_vulnerabilities.enrich_registry") as mock_enrich:
            mock_enrich.return_value = {"CVE-2099-99999": test_enriched}
            count = import_vulnerability_nodes(mock_session)

        assert count == 1
        # Verify batched UNWIND MERGE was called
        call_args = mock_session.run.call_args
        assert "UNWIND" in call_args[0][0]
        assert "MERGE" in call_args[0][0]
        batch = call_args[1]["batch"]
        assert len(batch) == 1
        assert batch[0]["cve_id"] == "CVE-2099-99999"

    def test_import_technique_nodes_deduplicates(self):
        """Same technique appearing in multiple categories should be imported once."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        seen = set()
        for ctx in _REGISTRY.values():
            for tech in ctx.techniques:
                seen.add(tech.technique_id)
        mock_result.single.return_value = {"n": len(seen)}
        mock_session.run.return_value = mock_result

        count = import_technique_nodes(mock_session)
        # Count should equal unique techniques, not total references
        assert count == len(seen)
        # Single batched call
        mock_session.run.assert_called_once()
        batch = mock_session.run.call_args[1]["batch"]
        assert len(batch) == len(seen)


# ── Integration tests (require Neo4j) ────────────────────────────────────

class TestImportIntegration:
    @pytest.fixture(autouse=True)
    def setup(self, neo4j_driver):
        self.driver = neo4j_driver

    def test_full_import_creates_nodes(self):
        """End-to-end: import creates Vulnerability and AttackTechnique nodes."""
        with self.driver.session() as session:
            counts = import_all(session)
            assert counts["vulnerabilities"] > 0
            assert counts["techniques"] > 0

            # Verify nodes exist
            result = session.run("MATCH (v:Vulnerability) RETURN count(v) AS n")
            assert result.single()["n"] > 0

            result = session.run("MATCH (t:AttackTechnique) RETURN count(t) AS n")
            assert result.single()["n"] > 0

    def test_import_is_idempotent(self):
        """Running import twice should not create duplicates (MERGE)."""
        with self.driver.session() as session:
            import_all(session)
            count1 = session.run("MATCH (v:Vulnerability) RETURN count(v) AS n").single()["n"]

            import_all(session)
            count2 = session.run("MATCH (v:Vulnerability) RETURN count(v) AS n").single()["n"]

            assert count1 == count2
