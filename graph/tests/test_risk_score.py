"""
test_risk_score.py — Tests for graph-native risk scoring (infer_risk_score.py).

Unit tests use mocked Neo4j sessions; integration tests require a live Neo4j.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from infer_risk_score import (
    _CATEGORY_CHECKS,
    _CRITICAL_CATEGORIES,
    _HIGH_CATEGORIES,
    _WEIGHT_INJECTION,
    infer,
)
from constants import (
    RISK_SCORE_PROPERTY,
    RISK_LEVEL_PROPERTY,
    ATTACK_CATEGORIES_PROPERTY,
)


# ── Unit tests ───────────────────────────────────────────────────────────────


class TestCategoryChecks:
    def test_category_checks_are_nonempty(self):
        """All category checks should be non-empty Cypher fragments."""
        assert len(_CATEGORY_CHECKS) > 0
        for cat, clause in _CATEGORY_CHECKS.items():
            assert isinstance(clause, str)
            assert len(clause.strip()) > 0, f"Empty check for {cat}"

    def test_injectable_fda_checks_fda_grant(self):
        clause = _CATEGORY_CHECKS["injectable_fda"]
        assert "kTCCServiceSystemPolicyAllFiles" in clause
        assert "injection_methods" in clause

    def test_file_acl_escalation_uses_user_path_not_impossible_app_edge(self):
        clause = _CATEGORY_CHECKS["file_acl_escalation"]
        assert "LOCAL_TO" in clause
        assert "CAN_WRITE" in clause
        assert "(app)-[:CAN_WRITE]" not in clause

    def test_mdm_risk_uses_configures_relationship(self):
        clause = _CATEGORY_CHECKS["mdm_risk"]
        assert "CONFIGURES" in clause
        assert "MDM_OVERGRANT" not in clause

    def test_physical_security_disabled_for_app_scoring(self):
        assert _CATEGORY_CHECKS["physical_security"].strip() == "false"

    def test_critical_categories_are_subset(self):
        """Critical categories should all have check clauses."""
        for cat in _CRITICAL_CATEGORIES:
            assert cat in _CATEGORY_CHECKS, (
                f"Critical category {cat} missing from checks"
            )

    def test_high_categories_are_subset(self):
        """High categories should all have check clauses."""
        for cat in _HIGH_CATEGORIES:
            assert cat in _CATEGORY_CHECKS, f"High category {cat} missing from checks"


class TestRiskConstants:
    def test_risk_property_names(self):
        assert RISK_SCORE_PROPERTY == "risk_score"
        assert RISK_LEVEL_PROPERTY == "risk_level"
        assert ATTACK_CATEGORIES_PROPERTY == "attack_categories"

    def test_weights_are_positive(self):
        assert _WEIGHT_INJECTION > 0


class TestInferFunction:
    def test_infer_calls_session_run(self):
        """infer() should call session.run multiple times for categorization + scoring."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 5}
        mock_session.run.return_value = mock_result

        count = infer(mock_session)

        # Should call run at least 3 times: categories, finding counts, risk score
        assert mock_session.run.call_count >= 3
        assert count == 5  # returns count from category query

    def test_infer_returns_int(self):
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 0}
        mock_session.run.return_value = mock_result

        result = infer(mock_session)
        assert isinstance(result, int)


# ── Integration tests (require Neo4j) ────────────────────────────────────


class TestRiskScoreIntegration:
    @pytest.fixture(autouse=True)
    def setup(self, neo4j_driver):
        self.driver = neo4j_driver

    def test_infer_on_empty_graph(self):
        """Risk scoring on empty graph should succeed with 0."""
        with self.driver.session() as session:
            count = infer(session)
            assert isinstance(count, int)

    def test_scored_apps_have_risk_level(self):
        """After scoring, apps with risk_score should also have risk_level."""
        with self.driver.session() as session:
            infer(session)
            result = session.run(
                """
                MATCH (app:Application)
                WHERE app.risk_score IS NOT NULL AND app.risk_level IS NULL
                RETURN count(app) AS n
                """
            )
            # No app should have risk_score without risk_level
            assert result.single()["n"] == 0
