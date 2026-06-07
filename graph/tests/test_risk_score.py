"""
test_risk_score.py — Tests for graph-native risk scoring (infer_risk_score.py).

Unit tests use mocked Neo4j sessions; integration tests require a live Neo4j.
"""

from __future__ import annotations

from unittest import TestCase

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import infer_risk_score as risk_score
from category_predicates import RISK_CATEGORY_PREDICATES
from infer_risk_score import (
    _CRITICAL_CATEGORIES,
    _HIGH_CATEGORIES,
    infer,
)


# ── Unit tests ───────────────────────────────────────────────────────────────


checks = TestCase()


class TestCategoryChecks:
    def test_category_checks_are_nonempty(self):
        """All category checks should be non-empty Cypher fragments."""
        checks.assertGreater(len(RISK_CATEGORY_PREDICATES), 0)
        for cat, clause in RISK_CATEGORY_PREDICATES.items():
            checks.assertTrue(isinstance(clause, str))
            checks.assertGreater(len(clause.strip()), 0, f"Empty check for {cat}")

    def test_injectable_fda_checks_fda_grant(self):
        clause = RISK_CATEGORY_PREDICATES["injectable_fda"]
        checks.assertIn("kTCCServiceSystemPolicyAllFiles", clause)
        checks.assertIn("injection_methods", clause)

    def test_file_acl_escalation_uses_user_path_not_impossible_app_edge(self):
        clause = RISK_CATEGORY_PREDICATES["file_acl_escalation"]
        checks.assertIn("LOCAL_TO", clause)
        checks.assertIn("CAN_WRITE", clause)
        checks.assertNotIn("(app)-[:CAN_WRITE]", clause)

    def test_mdm_risk_uses_configures_relationship(self):
        clause = RISK_CATEGORY_PREDICATES["mdm_risk"]
        checks.assertIn("CONFIGURES", clause)
        checks.assertNotIn("MDM_OVERGRANT", clause)

    def test_physical_security_disabled_for_app_scoring(self):
        checks.assertEqual(
            RISK_CATEGORY_PREDICATES["physical_security"].strip(), "false"
        )

    def test_critical_categories_are_subset(self):
        """Critical categories should all have check clauses."""
        for cat in _CRITICAL_CATEGORIES:
            checks.assertIn(
                cat,
                RISK_CATEGORY_PREDICATES,
                f"Critical category {cat} missing from checks",
            )

    def test_high_categories_are_subset(self):
        """High categories should all have check clauses."""
        for cat in _HIGH_CATEGORIES:
            checks.assertIn(
                cat,
                RISK_CATEGORY_PREDICATES,
                f"High category {cat} missing from checks",
            )


class TestInferFunction:
    def test_infer_returns_actual_scored_node_count(self):
        """infer() should return risk_score count, not category annotation count."""
        mock_session = MagicMock()
        category_result = MagicMock()
        category_result.single.return_value = {"n": 5}
        finding_result = MagicMock()
        scoring_result = MagicMock()
        scored_count_result = MagicMock()
        scored_count_result.single.return_value = {"n": 2}
        mock_session.run.side_effect = [
            category_result,
            finding_result,
            scoring_result,
            scored_count_result,
        ]

        count = infer(mock_session)

        checks.assertEqual(count, 2)

    def test_infer_propagates_session_failure(self):
        mock_session = MagicMock()
        mock_session.run.side_effect = RuntimeError("neo4j write failed")

        with pytest.raises(RuntimeError, match="neo4j write failed"):
            infer(mock_session)


# ── Integration tests (require Neo4j) ────────────────────────────────────


class TestRiskScoringBehavior:
    fixture_id = "risk-score-behavior"

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
            MATCH (n {risk_fixture: $fixture})
            DETACH DELETE n
            """,
            fixture=self.fixture_id,
        )

    def _app(self, session, key: str, **properties):
        payload = {
            "risk_fixture": self.fixture_id,
            "app_key": key,
            "name": key,
            "bundle_id": f"com.example.{key}",
            "injection_methods": [],
            "tier": 2,
            **properties,
        }
        session.run("CREATE (:Application $payload)", payload=payload)

    def _risk(self, session, key: str) -> dict:
        record = session.run(
            """
            MATCH (app:Application {risk_fixture: $fixture, app_key: $key})
            RETURN app.risk_score AS score,
                   app.risk_level AS level,
                   app.attack_categories AS categories
            """,
            fixture=self.fixture_id,
            key=key,
        ).single()
        return dict(record)

    def test_app_with_fda_dyld_tier_and_cve_scores_critical(self):
        with self.driver.session() as session:
            self._app(
                session,
                "critical-app",
                injection_methods=["dyld_insert_libraries"],
                tier=0,
            )
            session.run(
                """
                MATCH (app:Application {risk_fixture: $fixture, app_key: 'critical-app'})
                MERGE (perm:TCC_Permission {
                    service: 'kTCCServiceSystemPolicyAllFiles'
                })
                CREATE (v:Vulnerability {risk_fixture: $fixture, cve_id: 'CVE-2099-5000'})
                CREATE (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm)
                CREATE (app)-[:AFFECTED_BY]->(v)
                """,
                fixture=self.fixture_id,
            )

            infer(session)
            risk = self._risk(session, "critical-app")

            checks.assertEqual(risk["level"], "critical")
            checks.assertGreaterEqual(risk["score"], 8.0)
            checks.assertIn("injectable_fda", risk["categories"])

    def test_clean_app_scores_low(self):
        with self.driver.session() as session:
            self._app(session, "clean-app")

            infer(session)
            risk = self._risk(session, "clean-app")

            checks.assertEqual(risk["level"], "low")
            checks.assertLess(risk["score"], 3.0)

    def test_risk_score_is_capped_at_10(self, monkeypatch):
        monkeypatch.setattr(risk_score, "_WEIGHT_INJECTION", 20.0)
        with self.driver.session() as session:
            self._app(
                session,
                "capped-app",
                injection_methods=["dyld_insert_libraries"],
            )

            infer(session)
            risk = self._risk(session, "capped-app")

            checks.assertEqual(risk["score"], 10.0)
            checks.assertEqual(risk["level"], "critical")

    def test_injection_weight_dominates_network_exposure(self):
        with self.driver.session() as session:
            self._app(
                session,
                "injection-app",
                injection_methods=["dyld_insert_libraries"],
            )
            self._app(session, "network-app")
            session.run(
                """
                MATCH (app:Application {risk_fixture: $fixture, app_key: 'network-app'})
                CREATE (perm:TCC_Permission {
                    risk_fixture: $fixture,
                    service: 'kTCCServiceCamera'
                })
                CREATE (fw:FirewallPolicy {risk_fixture: $fixture})
                CREATE (app)-[:HAS_TCC_GRANT {allowed: true}]->(perm)
                CREATE (app)-[:HAS_FIREWALL_RULE]->(fw)
                """,
                fixture=self.fixture_id,
            )

            infer(session)
            injection_risk = self._risk(session, "injection-app")
            network_risk = self._risk(session, "network-app")

            checks.assertGreater(injection_risk["score"], network_risk["score"])
