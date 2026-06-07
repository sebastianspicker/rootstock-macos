"""
test_esf_enrichment.py — Tests for ESF event subscription enrichment.

Tests the extended infer_esf.py with monitoring gap detection.
"""

from __future__ import annotations

from unittest import TestCase

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from constants import ATTACKER_BUNDLE_ID
from infer_esf import _CRITICAL_ESF_EVENTS, _ESF_ENTITLEMENT, infer

TEST_MARKER = "rootstock-test-esf"


# ── Unit tests ───────────────────────────────────────────────────────────────

checks = TestCase()


class TestEsfConstants:
    def test_critical_events_defined(self):
        """Should have a non-empty list of critical ESF events."""
        checks.assertGreater(len(_CRITICAL_ESF_EVENTS), 10)

    def test_critical_events_are_auth_or_notify(self):
        """All critical events should be AUTH_ or NOTIFY_ prefixed."""
        for event in _CRITICAL_ESF_EVENTS:
            checks.assertTrue(
                event.startswith("AUTH_") or event.startswith("NOTIFY_"),
                f"Unexpected event prefix: {event}",
            )


class TestEsfInfer:
    def test_infer_calls_blind_monitoring(self):
        """infer() should create CAN_BLIND_MONITORING edges."""
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.single.return_value = {"n": 3}
        mock_session.run.return_value = mock_result

        count = infer(mock_session)
        checks.assertEqual(count, 3)

        # Should call run at least twice: blind monitoring + gap detection
        checks.assertGreaterEqual(mock_session.run.call_count, 2)

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

        checks.assertIsNotNone(gap_call, "Gap detection query not found")
        checks.assertIn("has_monitoring_gap", gap_call[0][0])


# ── Integration tests (require Neo4j) ────────────────────────────────────


class TestEsfIntegration:
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
            "MATCH (n {test_marker: $marker}) DETACH DELETE n",
            marker=TEST_MARKER,
        )

    def _seed_extension(
        self,
        session,
        identifier: str,
        events: list[str],
        *,
        extension_type: str = "endpoint_security",
        enabled: bool = True,
        containing_bundle: str | None = None,
    ) -> None:
        session.run(
            """
            CREATE (se:SystemExtension {
                identifier: $identifier,
                extension_type: $extension_type,
                enabled: $enabled,
                subscribed_events: $events,
                containing_app_bundle_id: $containing_bundle,
                test_marker: $marker
            })
            """,
            identifier=identifier,
            extension_type=extension_type,
            enabled=enabled,
            events=events,
            containing_bundle=containing_bundle,
            marker=TEST_MARKER,
        )

    def _monitoring_status(self, session, identifier: str):
        result = session.run(
            """
            MATCH (se:SystemExtension {identifier: $identifier})
            RETURN se.has_monitoring_gap AS gap,
                   se.monitoring_gap_count AS gap_count
            """,
            identifier=identifier,
        )
        return result.single()

    def _seed_esf_app(
        self,
        session,
        app_key: str,
        bundle_id: str,
        *,
        entitled: bool = True,
        injection_methods: list[str] | None = None,
    ) -> None:
        session.run(
            """
            MERGE (ent:Entitlement {name: $esf_entitlement})
            CREATE (app:Application {
                app_key: $app_key,
                bundle_id: $bundle_id,
                name: $app_key,
                injection_methods: $injection_methods,
                test_marker: $marker
            })
            WITH app, ent
            FOREACH (_ IN CASE WHEN $entitled THEN [1] ELSE [] END |
                CREATE (app)-[:HAS_ENTITLEMENT]->(ent)
            )
            """,
            app_key=app_key,
            bundle_id=bundle_id,
            injection_methods=injection_methods or [],
            entitled=entitled,
            esf_entitlement=_ESF_ENTITLEMENT,
            marker=TEST_MARKER,
        )

    def _blind_monitoring_edges(self, session, app_key: str) -> int:
        result = session.run(
            """
            MATCH (:Application {app_key: $app_key})
                  -[rel:CAN_BLIND_MONITORING]->
                  (:SystemExtension)
            RETURN count(rel) AS n
            """,
            app_key=app_key,
        )
        return result.single()["n"]

    def test_infer_on_empty_graph(self):
        """ESF inference on empty graph should return 0."""
        with self.driver.session() as session:
            count = infer(session)
            checks.assertEqual(count, 0)

    def test_complete_subscriber_has_no_monitoring_gap(self):
        with self.driver.session() as session:
            self._seed_extension(
                session,
                "test-esf-complete",
                list(_CRITICAL_ESF_EVENTS),
            )

            infer(session)

            status = self._monitoring_status(session, "test-esf-complete")
            checks.assertIs(status["gap"], False)
            checks.assertEqual(status["gap_count"], 0)

    def test_missing_auth_event_sets_monitoring_gap(self):
        with self.driver.session() as session:
            events = [e for e in _CRITICAL_ESF_EVENTS if e != "AUTH_EXEC"]
            self._seed_extension(session, "test-esf-missing-auth", events)

            infer(session)

            status = self._monitoring_status(session, "test-esf-missing-auth")
            checks.assertIs(status["gap"], True)
            checks.assertEqual(status["gap_count"], 1)

    def test_notify_only_coverage_leaves_auth_gap(self):
        with self.driver.session() as session:
            notify_events = [e for e in _CRITICAL_ESF_EVENTS if e.startswith("NOTIFY_")]
            auth_count = len([e for e in _CRITICAL_ESF_EVENTS if e.startswith("AUTH_")])
            self._seed_extension(session, "test-esf-notify-only", notify_events)

            infer(session)

            status = self._monitoring_status(session, "test-esf-notify-only")
            checks.assertIs(status["gap"], True)
            checks.assertEqual(status["gap_count"], auth_count)

    def test_unknown_and_duplicate_events_do_not_create_false_gap(self):
        with self.driver.session() as session:
            events = list(_CRITICAL_ESF_EVENTS) + ["AUTH_EXEC", "FUTURE_EVENT"]
            self._seed_extension(session, "test-esf-unknown-duplicate", events)

            infer(session)

            status = self._monitoring_status(session, "test-esf-unknown-duplicate")
            checks.assertIs(status["gap"], False)
            checks.assertEqual(status["gap_count"], 0)

    def test_non_endpoint_security_extension_is_not_marked_as_gap(self):
        with self.driver.session() as session:
            self._seed_extension(
                session,
                "test-esf-network-extension",
                [],
                extension_type="network_extension",
            )

            infer(session)

            status = self._monitoring_status(session, "test-esf-network-extension")
            checks.assertIsNone(status["gap"])
            checks.assertIsNone(status["gap_count"])

    def test_injectable_esf_client_edges_require_entitlement_and_matching_extension(
        self,
    ):
        with self.driver.session() as session:
            self._seed_esf_app(
                session,
                "test-esf-positive-app",
                "com.example.esf.positive",
                injection_methods=["dyld_insert_libraries"],
            )
            self._seed_esf_app(
                session,
                "test-esf-negative-app",
                "com.example.esf.negative",
                entitled=False,
                injection_methods=["dyld_insert_libraries"],
            )
            self._seed_extension(
                session,
                "test-esf-positive-extension",
                list(_CRITICAL_ESF_EVENTS),
                containing_bundle="com.example.esf.positive",
            )

            infer(session)

            checks.assertEqual(
                self._blind_monitoring_edges(session, "test-esf-positive-app"), 1
            )
            checks.assertEqual(
                self._blind_monitoring_edges(session, "test-esf-negative-app"), 0
            )

    def test_attacker_bundle_is_not_marked_as_blind_monitoring_source(self):
        with self.driver.session() as session:
            self._seed_esf_app(
                session,
                "test-esf-attacker-app",
                ATTACKER_BUNDLE_ID,
                injection_methods=["dyld_insert_libraries"],
            )
            self._seed_extension(
                session,
                "test-esf-attacker-extension",
                list(_CRITICAL_ESF_EVENTS),
                containing_bundle=ATTACKER_BUNDLE_ID,
            )

            infer(session)

            checks.assertEqual(
                self._blind_monitoring_edges(session, "test-esf-attacker-app"), 0
            )
