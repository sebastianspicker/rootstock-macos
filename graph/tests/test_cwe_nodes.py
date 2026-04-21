"""
test_cwe_nodes.py — Tests for CWE weakness-class node import.

Unit tests validate the CWE registry and import functions.
Integration tests verify CWE nodes and HAS_CWE edges in Neo4j.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from cve_reference import CWE_REGISTRY, CweReference
from import_vulnerabilities import import_cwe_nodes, import_cwe_edges, import_all


# ── CWE Registry tests ──────────────────────────────────────────────────────

class TestCweRegistry:
    def test_registry_has_entries(self):
        assert len(CWE_REGISTRY) >= 19

    def test_all_entries_are_cwe_references(self):
        for cwe_id, ref in CWE_REGISTRY.items():
            assert isinstance(ref, CweReference)
            assert ref.cwe_id == cwe_id
            assert ref.cwe_id.startswith("CWE-")

    def test_all_entries_have_category(self):
        """Every CWE entry should have a non-empty category."""
        valid_categories = {
            "memory_safety", "access_control", "input_validation",
            "authentication", "information_disclosure", "concurrency", "other",
        }
        for cwe_id, ref in CWE_REGISTRY.items():
            assert ref.category in valid_categories, f"{cwe_id} has invalid category: {ref.category}"

    def test_memory_safety_cwes(self):
        """CWE-416 (UAF), CWE-120 (BOF), CWE-787 (OOB) should be memory_safety."""
        for cwe_id in ["CWE-416", "CWE-120", "CWE-787", "CWE-122"]:
            assert CWE_REGISTRY[cwe_id].category == "memory_safety"


# ── Import function tests ────────────────────────────────────────────────────

class TestCweImportFunctions:
    def test_import_cwe_nodes_calls_merge(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": len(CWE_REGISTRY)}
        mock_session.run.return_value = mock_result

        count = import_cwe_nodes(mock_session)
        assert count == len(CWE_REGISTRY)

        # Batched: single UNWIND call with all CWEs
        mock_session.run.assert_called_once()
        call_args = mock_session.run.call_args
        assert "UNWIND" in call_args[0][0]
        assert "MERGE" in call_args[0][0]
        batch = call_args[1]["batch"]
        assert len(batch) == len(CWE_REGISTRY)
        assert all("cwe_id" in entry for entry in batch)

    def test_import_cwe_edges_runs_query(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 10}
        mock_session.run.return_value = mock_result

        count = import_cwe_edges(mock_session)
        assert count == 10
        assert "HAS_CWE" in mock_session.run.call_args[0][0]

    def test_import_all_includes_cwe(self):
        """import_all should include cwe_nodes and has_cwe_edges in result."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 0}
        mock_session.run.return_value = mock_result

        with patch("import_vulnerabilities.enrich_registry") as mock_enrich:
            mock_enrich.return_value = {}
            counts = import_all(mock_session)

        assert "cwe_nodes" in counts
        assert "has_cwe_edges" in counts


# ── Integration tests (require Neo4j) ────────────────────────────────────

class TestCweIntegration:
    @pytest.fixture(autouse=True)
    def setup(self, neo4j_driver):
        self.driver = neo4j_driver

    def test_cwe_nodes_created(self):
        """CWE nodes should be created from the registry."""
        with self.driver.session() as session:
            import_cwe_nodes(session)
            result = session.run("MATCH (c:CWE) RETURN count(c) AS n")
            assert result.single()["n"] >= 19

    def test_cwe_nodes_have_category(self):
        """All CWE nodes should have a category property."""
        with self.driver.session() as session:
            import_cwe_nodes(session)
            result = session.run(
                "MATCH (c:CWE) WHERE c.category IS NULL RETURN count(c) AS n"
            )
            assert result.single()["n"] == 0

    def test_cwe_import_is_idempotent(self):
        """Running import twice should not create duplicates."""
        with self.driver.session() as session:
            import_cwe_nodes(session)
            count1 = session.run("MATCH (c:CWE) RETURN count(c) AS n").single()["n"]
            import_cwe_nodes(session)
            count2 = session.run("MATCH (c:CWE) RETURN count(c) AS n").single()["n"]
            assert count1 == count2
