"""
test_cwe_nodes.py — Tests for CWE weakness-class node import.

Unit tests validate the CWE registry and import functions.
Integration tests verify CWE nodes and HAS_CWE edges in Neo4j.
"""

from __future__ import annotations

from unittest import TestCase

from unittest.mock import MagicMock, patch

import pytest

from cve_reference import CWE_REGISTRY, CweReference
from import_vulnerabilities import import_cwe_nodes, import_cwe_edges, import_all

TEST_CWE_IDS = ["CWE-999"]
TEST_CVE_IDS = ["CVE-2099-20001", "CVE-2099-20002"]


# ── CWE Registry tests ──────────────────────────────────────────────────────

checks = TestCase()


class TestCweRegistry:
    def test_registry_has_entries(self):
        checks.assertGreaterEqual(len(CWE_REGISTRY), 19)

    def test_all_entries_are_cwe_references(self):
        for cwe_id, ref in CWE_REGISTRY.items():
            checks.assertTrue(isinstance(ref, CweReference))
            checks.assertEqual(ref.cwe_id, cwe_id)
            checks.assertTrue(ref.cwe_id.startswith("CWE-"))

    def test_all_entries_have_category(self):
        """Every CWE entry should have a non-empty category."""
        valid_categories = {
            "memory_safety",
            "access_control",
            "input_validation",
            "authentication",
            "information_disclosure",
            "concurrency",
            "other",
        }
        for cwe_id, ref in CWE_REGISTRY.items():
            checks.assertIn(
                ref.category,
                valid_categories,
                f"{cwe_id} has invalid category: {ref.category}",
            )

    def test_memory_safety_cwes(self):
        """CWE-416 (UAF), CWE-120 (BOF), CWE-787 (OOB) should be memory_safety."""
        for cwe_id in ["CWE-416", "CWE-120", "CWE-787", "CWE-122"]:
            checks.assertEqual(CWE_REGISTRY[cwe_id].category, "memory_safety")


# ── Import function tests ────────────────────────────────────────────────────


class TestCweImportFunctions:
    def test_import_cwe_nodes_calls_merge(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": len(CWE_REGISTRY)}
        mock_session.run.return_value = mock_result

        count = import_cwe_nodes(mock_session)
        checks.assertEqual(count, len(CWE_REGISTRY))

        # Batched: single UNWIND call with all CWEs
        mock_session.run.assert_called_once()
        call_args = mock_session.run.call_args
        checks.assertIn("UNWIND", call_args[0][0])
        checks.assertIn("MERGE", call_args[0][0])
        batch = call_args[1]["batch"]
        checks.assertEqual(len(batch), len(CWE_REGISTRY))
        checks.assertTrue(all("cwe_id" in entry for entry in batch))

    def test_import_cwe_edges_runs_query(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 10}
        mock_session.run.return_value = mock_result

        count = import_cwe_edges(mock_session)
        checks.assertEqual(count, 10)
        checks.assertIn("HAS_CWE", mock_session.run.call_args[0][0])

    def test_import_all_includes_cwe(self):
        """import_all should include cwe_nodes and has_cwe_edges in result."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 0}
        mock_session.run.return_value = mock_result

        with patch("import_vulnerabilities.enrich_registry") as mock_enrich:
            mock_enrich.return_value = {}
            counts = import_all(mock_session)

        checks.assertIn("cwe_nodes", counts)
        checks.assertIn("has_cwe_edges", counts)


# ── Integration tests (require Neo4j) ────────────────────────────────────


class TestCweIntegration:
    @pytest.fixture(autouse=True)
    def setup(self, neo4j_driver):
        self.driver = neo4j_driver
        with self.driver.session() as session:
            self._cleanup(session)
        yield
        with self.driver.session() as session:
            self._cleanup(session)

    def _cleanup(self, session):
        session.run(
            """
            MATCH (n)
            WHERE n.cwe_id IN $cwe_ids OR n.cve_id IN $cve_ids
            DETACH DELETE n
            """,
            cwe_ids=TEST_CWE_IDS,
            cve_ids=TEST_CVE_IDS,
        )

    def test_cwe_nodes_created(self):
        """CWE nodes should be created from the registry."""
        with self.driver.session() as session:
            import_cwe_nodes(session)
            result = session.run("MATCH (c:CWE) RETURN count(c) AS n")
            checks.assertGreaterEqual(result.single()["n"], 19)

    def test_cwe_nodes_have_category(self):
        """All CWE nodes should have a category property."""
        with self.driver.session() as session:
            import_cwe_nodes(session)
            result = session.run(
                "MATCH (c:CWE) WHERE c.category IS NULL RETURN count(c) AS n"
            )
            checks.assertEqual(result.single()["n"], 0)

    def test_cwe_import_is_idempotent(self):
        """Running import twice should not create duplicates."""
        with self.driver.session() as session:
            import_cwe_nodes(session)
            count1 = session.run("MATCH (c:CWE) RETURN count(c) AS n").single()["n"]
            import_cwe_nodes(session)
            count2 = session.run("MATCH (c:CWE) RETURN count(c) AS n").single()["n"]
            checks.assertEqual(count1, count2)

    def test_cwe_edges_attach_only_to_declared_vulnerability_cwe_ids(self):
        fixture_cwe = CweReference("CWE-999", "Fixture Weakness", "other")

        with self.driver.session() as session:
            session.run(
                """
                CREATE (:Vulnerability {
                    cve_id: 'CVE-2099-20001',
                    cwe_ids: ['CWE-999', 'CWE-MISSING']
                })
                CREATE (:Vulnerability {
                    cve_id: 'CVE-2099-20002',
                    cwe_ids: []
                })
                """
            )

            with patch("import_vulnerabilities.CWE_REGISTRY", {"CWE-999": fixture_cwe}):
                import_cwe_nodes(session)
                import_cwe_edges(session)

            result = session.run(
                """
                MATCH (v:Vulnerability)-[:HAS_CWE]->(c:CWE)
                WHERE v.cve_id IN $cve_ids
                RETURN v.cve_id AS cve_id,
                       collect(c.cwe_id) AS cwe_ids,
                       collect(c.category) AS categories
                """,
                cve_ids=TEST_CVE_IDS,
            )
            records = [dict(record) for record in result]
            checks.assertEqual(
                records,
                [
                    {
                        "cve_id": "CVE-2099-20001",
                        "cwe_ids": ["CWE-999"],
                        "categories": ["other"],
                    }
                ],
            )
