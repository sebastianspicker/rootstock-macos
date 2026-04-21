"""
test_esf_enrichment.py — Tests for ESF event subscription enrichment.

Tests the extended infer_esf.py with monitoring gap detection.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from infer_esf import _CRITICAL_ESF_EVENTS, infer


# ── Unit tests ───────────────────────────────────────────────────────────────

class TestEsfConstants:
    def test_critical_events_defined(self):
        """Should have a non-empty list of critical ESF events."""
        assert len(_CRITICAL_ESF_EVENTS) > 10

    def test_critical_events_are_auth_or_notify(self):
        """All critical events should be AUTH_ or NOTIFY_ prefixed."""
        for event in _CRITICAL_ESF_EVENTS:
            assert event.startswith("AUTH_") or event.startswith("NOTIFY_"), \
                f"Unexpected event prefix: {event}"


class TestEsfInfer:
    def test_infer_calls_blind_monitoring(self):
        """infer() should create CAN_BLIND_MONITORING edges."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 3}
        mock_session.run.return_value = mock_result

        count = infer(mock_session)
        assert count == 3

        # Should call run at least twice: blind monitoring + gap detection
        assert mock_session.run.call_count >= 2

    def test_infer_passes_critical_events(self):
        """Gap detection query should receive critical events list."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 0}
        mock_session.run.return_value = mock_result

        infer(mock_session)

        # Find the gap detection call (has critical_events parameter)
        gap_call = None
        for c in mock_session.run.call_args_list:
            kwargs = c[1] if len(c) > 1 else {}
            if "critical_events" in kwargs:
                gap_call = c
                break

        assert gap_call is not None, "Gap detection query not found"
        assert "has_monitoring_gap" in gap_call[0][0]


# ── Integration tests (require Neo4j) ────────────────────────────────────

class TestEsfIntegration:
    @pytest.fixture(autouse=True)
    def setup(self, neo4j_driver):
        self.driver = neo4j_driver

    def test_infer_on_empty_graph(self):
        """ESF inference on empty graph should return 0."""
        with self.driver.session() as session:
            count = infer(session)
            assert count == 0
