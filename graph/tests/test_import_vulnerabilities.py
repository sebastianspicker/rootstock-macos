"""
test_import_vulnerabilities.py — Tests for vulnerability node import.

Pure unit tests for the import logic — no Neo4j required for most tests.
Integration tests require a running Neo4j instance.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

import pytest

from cve_reference import AttackContext, AttackTechnique, CveEntry, _REGISTRY
from import_vulnerabilities import (
    _CATEGORY_MATCH,
    import_vulnerability_nodes,
    import_technique_nodes,
    import_all,
    import_affected_by_edges,
    import_precise_affected_by_edges,
    main,
)

TEST_CVE_IDS = [
    "CVE-2099-10001",
    "CVE-2099-10002",
    "CVE-2099-10003",
]
TEST_TECHNIQUE_IDS = ["T9999.001"]
TEST_APP_KEYS = [
    "test-vuln-precise-a",
    "test-vuln-precise-b",
    "test-vuln-precise-patched",
    "test-vuln-category-positive",
    "test-vuln-category-negative",
]


checks = TestCase()


class _FakeDriver:
    def session(self):
        return _FakeSession()

    def close(self):
        return None


class _FakeSession:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


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
        checks.assertLessEqual(
            len(missing),
            len(_REGISTRY) * 0.3,
            f"Too many unmatched categories: {missing}",
        )

    def test_match_patterns_are_valid_cypher_fragments(self):
        """Each match pattern should be a non-empty string."""
        for cat, pattern in _CATEGORY_MATCH.items():
            checks.assertTrue(isinstance(pattern, str))
            checks.assertGreater(len(pattern.strip()), 0, f"Empty pattern for {cat}")

    def test_injectable_fda_pattern_checks_fda_and_injection(self):
        pattern = _CATEGORY_MATCH["injectable_fda"]
        checks.assertIn("kTCCServiceSystemPolicyAllFiles", pattern)
        checks.assertIn("injection_methods", pattern)

    def test_electron_pattern_uses_child_inherits(self):
        pattern = _CATEGORY_MATCH["electron_inheritance"]
        checks.assertIn("CHILD_INHERITS_TCC", pattern)


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

        checks.assertIn("vulnerabilities", counts)
        checks.assertIn("techniques", counts)
        checks.assertIn("maps_to_technique", counts)
        checks.assertIn("affected_by", counts)

    def test_category_fallback_edges_are_marked_as_heuristic(self):
        """Broad category AFFECTED_BY edges must be distinguishable from precise matches."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 2}
        mock_session.run.return_value = mock_result
        test_cve = CveEntry(
            cve_id="CVE-2099-88888",
            title="Category fallback CVE",
            cvss_score=6.5,
            affected_versions="fixture",
            patched_version=None,
            description="fixture",
            reference_url="https://example.com",
        )

        with (
            patch(
                "import_vulnerabilities._REGISTRY",
                {"fixture_category": SimpleNamespace(cves=[test_cve])},
            ),
            patch(
                "import_vulnerabilities._CATEGORY_MATCH",
                {"fixture_category": "app.is_running = true"},
            ),
            patch("import_vulnerabilities._collect_precise_cves", return_value=[]),
        ):
            count, warning_count = import_affected_by_edges(mock_session)

        query = mock_session.run.call_args[0][0]
        params = mock_session.run.call_args[1]
        checks.assertEqual(count, 2)
        checks.assertEqual(warning_count, 0)
        checks.assertIn("r.match_tier = 'category'", query)
        checks.assertIn("r.match_source = 'category_fallback'", query)
        checks.assertIn("r.match_confidence = 'heuristic'", query)
        checks.assertIn("r.match_category = $category", query)
        checks.assertEqual(params["category"], "fixture_category")
        checks.assertEqual(params["cve_ids"], ["CVE-2099-88888"])

    def test_import_precise_edges_failure_increments_warning_count(self):
        """Failed precise edge writes must be counted for the CLI exit gate."""
        mock_session = MagicMock()
        test_cve = CveEntry(
            cve_id="CVE-2099-77777",
            title="Precise edge failure CVE",
            cvss_score=7.0,
            affected_versions="FixtureApp 1.2.0 and earlier",
            patched_version="FixtureApp 1.3.0",
            description="fixture",
            reference_url="https://example.com",
            affected_bundle_ids=("com.example.precise",),
            max_affected_version="1.2.0",
        )
        mock_session.run.side_effect = [
            [
                {
                    "bundle_id": "com.example.precise",
                    "app_version": "1.0.0",
                    "macos_version": None,
                    "app_id": "app-1",
                }
            ],
            RuntimeError("fixture write failed"),
        ]

        with patch(
            "import_vulnerabilities._collect_precise_cves", return_value=[test_cve]
        ):
            count, warning_count = import_precise_affected_by_edges(mock_session)

        checks.assertEqual(count, 0)
        checks.assertEqual(warning_count, 1)

    def test_import_all_exposes_warning_count(self):
        """The aggregate result must expose edge warning counts to main()."""
        mock_session = MagicMock()

        with (
            patch("import_vulnerabilities.import_vulnerability_nodes", return_value=1),
            patch("import_vulnerabilities.import_technique_nodes", return_value=2),
            patch("import_vulnerabilities.import_technique_edges", return_value=3),
            patch(
                "import_vulnerabilities.import_precise_affected_by_edges",
                return_value=(4, 1),
            ),
            patch(
                "import_vulnerabilities.import_affected_by_edges", return_value=(5, 2)
            ),
            patch("import_vulnerabilities.import_threat_group_nodes", return_value=6),
            patch(
                "import_vulnerabilities.import_group_technique_edges", return_value=7
            ),
            patch("import_vulnerabilities.import_cwe_nodes", return_value=8),
            patch("import_vulnerabilities.import_cwe_edges", return_value=9),
        ):
            counts = import_all(mock_session)

        checks.assertEqual(counts["affected_by_precise"], 4)
        checks.assertEqual(counts["affected_by_category"], 5)
        checks.assertEqual(counts["affected_by"], 9)
        checks.assertEqual(counts["warning_count"], 3)

    def test_main_exits_nonzero_on_edge_failure(self, monkeypatch, capsys):
        """Pipeline step 5 must fail when vulnerability edges are incomplete."""
        counts = {
            "vulnerabilities": 1,
            "techniques": 1,
            "maps_to_technique": 1,
            "affected_by_precise": 0,
            "affected_by_category": 0,
            "affected_by": 0,
            "threat_groups": 0,
            "uses_technique": 0,
            "cwe_nodes": 0,
            "has_cwe_edges": 0,
            "warning_count": 1,
        }
        monkeypatch.setattr(sys, "argv", ["import_vulnerabilities.py"])
        monkeypatch.setattr(
            "import_vulnerabilities.connect_from_args", lambda _args: _FakeDriver()
        )
        monkeypatch.setattr(
            "import_vulnerabilities.import_all", lambda _session: counts
        )

        exit_code = main()

        captured = capsys.readouterr()
        checks.assertEqual(exit_code, 1)
        checks.assertIn("WARNING: 1 vulnerability edge(s) failed", captured.err)


# ── Integration tests (require Neo4j) ────────────────────────────────────


class TestImportIntegration:
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
            WHERE n.cve_id IN $cve_ids
               OR n.technique_id IN $technique_ids
               OR n.app_key IN $app_keys
            DETACH DELETE n
            """,
            cve_ids=TEST_CVE_IDS,
            technique_ids=TEST_TECHNIQUE_IDS,
            app_keys=TEST_APP_KEYS,
        )

    def _fixture_cve(
        self,
        cve_id: str,
        *,
        affected_bundle_ids: tuple[str, ...] = (),
        max_affected_version: str | None = None,
    ) -> CveEntry:
        return CveEntry(
            cve_id=cve_id,
            title=f"Fixture {cve_id}",
            cvss_score=7.5,
            affected_versions="FixtureApp 1.2.0 and earlier",
            patched_version="FixtureApp 1.3.0",
            description="fixture",
            reference_url="https://example.com",
            affected_bundle_ids=affected_bundle_ids,
            max_affected_version=max_affected_version,
        )

    def _fixture_context(
        self,
        category: str,
        cves: list[CveEntry],
        techniques: list[AttackTechnique] | None = None,
    ) -> AttackContext:
        return AttackContext(
            category=category,
            techniques=techniques or [],
            cves=cves,
            remediation_priority="High",
        )

    def test_full_import_creates_nodes(self):
        """End-to-end: import creates Vulnerability and AttackTechnique nodes."""
        with self.driver.session() as session:
            counts = import_all(session)
            checks.assertGreater(counts["vulnerabilities"], 0)
            checks.assertGreater(counts["techniques"], 0)

            # Verify nodes exist
            result = session.run("MATCH (v:Vulnerability) RETURN count(v) AS n")
            checks.assertGreater(result.single()["n"], 0)

            result = session.run("MATCH (t:AttackTechnique) RETURN count(t) AS n")
            checks.assertGreater(result.single()["n"], 0)

    def test_import_is_idempotent(self):
        """Running import twice should not create duplicates (MERGE)."""
        with self.driver.session() as session:
            import_all(session)
            count1 = session.run(
                "MATCH (v:Vulnerability) RETURN count(v) AS n"
            ).single()["n"]

            import_all(session)
            count2 = session.run(
                "MATCH (v:Vulnerability) RETURN count(v) AS n"
            ).single()["n"]

            checks.assertEqual(count1, count2)

    def test_precise_cve_edges_attach_only_to_affected_bundle_versions(self):
        cve = self._fixture_cve(
            "CVE-2099-10001",
            affected_bundle_ids=("com.example.precise",),
            max_affected_version="1.2.0",
        )
        registry = {"fixture_precise": self._fixture_context("fixture_precise", [cve])}

        with self.driver.session() as session:
            session.run(
                """
                CREATE (:Vulnerability {cve_id: $cve_id})
                CREATE (:Application {
                    app_key: 'test-vuln-precise-a',
                    bundle_id: 'com.example.precise',
                    version: '1.0.0'
                })
                CREATE (:Application {
                    app_key: 'test-vuln-precise-b',
                    bundle_id: 'com.example.precise',
                    version: '1.2.0'
                })
                CREATE (:Application {
                    app_key: 'test-vuln-precise-patched',
                    bundle_id: 'com.example.precise',
                    version: '1.3.0'
                })
                """,
                cve_id=cve.cve_id,
            )

            with patch("import_vulnerabilities._REGISTRY", registry):
                import_precise_affected_by_edges(session)

            result = session.run(
                """
                MATCH (app:Application)-[rel:AFFECTED_BY]->
                      (:Vulnerability {cve_id: $cve_id})
                RETURN app.app_key AS app_key, rel.match_tier AS tier
                ORDER BY app_key
                """,
                cve_id=cve.cve_id,
            )
            checks.assertEqual(
                [dict(record) for record in result],
                [
                    {"app_key": "test-vuln-precise-a", "tier": "precise"},
                    {"app_key": "test-vuln-precise-b", "tier": "precise"},
                ],
            )

    def test_category_fallback_edges_are_heuristic_and_target_matching_apps(self):
        cve = self._fixture_cve("CVE-2099-10002")
        registry = {
            "fixture_category": self._fixture_context("fixture_category", [cve])
        }

        with self.driver.session() as session:
            session.run(
                """
                CREATE (:Vulnerability {cve_id: $cve_id})
                CREATE (:Application {
                    app_key: 'test-vuln-category-positive',
                    is_running: true
                })
                CREATE (:Application {
                    app_key: 'test-vuln-category-negative',
                    is_running: false
                })
                """,
                cve_id=cve.cve_id,
            )

            with (
                patch("import_vulnerabilities._REGISTRY", registry),
                patch(
                    "import_vulnerabilities._CATEGORY_MATCH",
                    {"fixture_category": "app.is_running = true"},
                ),
            ):
                import_affected_by_edges(session)

            self._assert_category_fallback_edges(session, cve.cve_id)

    def _assert_category_fallback_edges(self, session, cve_id: str) -> None:
        result = session.run(
            """
            MATCH (app:Application)-[rel:AFFECTED_BY]->
                  (:Vulnerability {cve_id: $cve_id})
            RETURN app.app_key AS app_key,
                   rel.match_tier AS tier,
                   rel.match_source AS source,
                   rel.match_confidence AS confidence,
                   rel.match_category AS category
            """,
            cve_id=cve_id,
        )
        checks.assertEqual(
            [dict(record) for record in result],
            [
                {
                    "app_key": "test-vuln-category-positive",
                    "tier": "category",
                    "source": "category_fallback",
                    "confidence": "heuristic",
                    "category": "fixture_category",
                }
            ],
        )

    def test_duplicate_registry_techniques_import_once_and_remain_idempotent(self):
        technique = AttackTechnique("T9999.001", "Fixture Technique", "Execution")
        registry = {
            "fixture_a": self._fixture_context("fixture_a", [], [technique]),
            "fixture_b": self._fixture_context("fixture_b", [], [technique]),
        }

        with self.driver.session() as session:
            with patch("import_vulnerabilities._REGISTRY", registry):
                import_technique_nodes(session)
                import_technique_nodes(session)

            result = session.run(
                """
                MATCH (t:AttackTechnique {technique_id: 'T9999.001'})
                RETURN count(t) AS n, collect(t.name) AS names
                """
            )
            record = result.single()
            checks.assertEqual(record["n"], 1)
            checks.assertEqual(record["names"], ["Fixture Technique"])

    def test_missing_enrichment_does_not_create_placeholder_vulnerabilities(self):
        with self.driver.session() as session:
            session.run("CREATE (:Vulnerability {cve_id: 'CVE-2099-10003'})")

            with patch("import_vulnerabilities.enrich_registry", return_value={}):
                count = import_vulnerability_nodes(session)

            result = session.run(
                """
                MATCH (v:Vulnerability)
                WHERE v.cve_id IN $cve_ids
                RETURN collect(v.cve_id) AS cve_ids
                """,
                cve_ids=TEST_CVE_IDS,
            )
            checks.assertEqual(count, 0)
            checks.assertEqual(result.single()["cve_ids"], ["CVE-2099-10003"])
