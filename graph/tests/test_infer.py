"""
test_infer.py — Integration tests for the Rootstock inference engine.

Tests use isolated synthetic nodes tagged with TEST_SCAN_ID so they can be
cleaned up after each test. Neo4j is required; tests skip if unavailable.

Usage:
    pytest graph/tests/test_infer.py -v
"""

from __future__ import annotations

import pytest

from conftest import cleanup_test_nodes
from constants import ATTACKER_BUNDLE_ID, ALLOW_DYLD_ENTITLEMENT

TEST_SCAN_ID = "test-infer-00000000-0000-0000-0000-000000000002"


@pytest.fixture(scope="module")
def session(neo4j_driver):
    """Module-scoped Neo4j session with cleanup."""
    with neo4j_driver.session() as s:
        yield s
    with neo4j_driver.session() as s:
        cleanup_test_nodes(s, TEST_SCAN_ID)


def _seed_graph(session) -> None:
    """
    Seed 3 test apps with known properties and relationships.

    App A (test.app.alpha):  has FDA, library_validation=false → injectable via missing_library_validation
    App B (test.app.bravo):  Electron, has Screen Recording   → injectable via CHILD_INHERITS_TCC
    App C (test.app.charlie): has AppleEvents grant           → can send Apple Events to A and B
    """
    session.run(
        """
        MERGE (fda:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        ON CREATE SET fda.display_name = 'Full Disk Access'
        MERGE (screen:TCC_Permission {service: 'kTCCServiceScreenCapture'})
        ON CREATE SET screen.display_name = 'Screen Recording'
        MERGE (events:TCC_Permission {service: 'kTCCServiceAppleEvents'})
        ON CREATE SET events.display_name = 'Automation'

        MERGE (appA:Application {bundle_id: 'test.app.alpha'})
        SET appA.name = 'Test App Alpha',
            appA.path = '/Applications/Alpha.app',
            appA.hardened_runtime = false,
            appA.library_validation = false,
            appA.is_electron = false, appA.is_system = false, appA.signed = true,
            appA.injection_methods = ['missing_library_validation'],
            appA.scan_id = $scan_id

        MERGE (appB:Application {bundle_id: 'test.app.bravo'})
        SET appB.name = 'Test App Bravo',
            appB.path = '/Applications/Bravo.app',
            appB.hardened_runtime = false,
            appB.library_validation = false,
            appB.is_electron = true, appB.is_system = false, appB.signed = true,
            appB.injection_methods = ['missing_library_validation', 'electron_env_var'],
            appB.scan_id = $scan_id

        MERGE (appC:Application {bundle_id: 'test.app.charlie'})
        SET appC.name = 'Test App Charlie',
            appC.path = '/Applications/Charlie.app',
            appC.hardened_runtime = true,
            appC.library_validation = true,
            appC.is_electron = false, appC.is_system = false, appC.signed = true,
            appC.injection_methods = [],
            appC.scan_id = $scan_id

        MERGE (appA)-[:HAS_TCC_GRANT {scope: 'user', allowed: true}]->(fda)
        MERGE (appB)-[:HAS_TCC_GRANT {scope: 'user', allowed: true}]->(screen)
        MERGE (appC)-[:HAS_TCC_GRANT {scope: 'user', allowed: true}]->(events)

        MERGE (dyld_ent:Entitlement {name: $allow_dyld})
        SET dyld_ent.is_private = false, dyld_ent.category = 'injection'
        MERGE (appB)-[:HAS_ENTITLEMENT]->(dyld_ent)
        """,
        scan_id=TEST_SCAN_ID,
        allow_dyld=ALLOW_DYLD_ENTITLEMENT,
    )


class TestInferInjection:
    def test_can_inject_into_missing_library_validation(self, session):
        _seed_graph(session)
        from infer_injection import infer
        infer(session)

        result = session.run(
            """
            MATCH (attacker:Application {bundle_id: $attacker_id})
                  -[r:CAN_INJECT_INTO {method: 'missing_library_validation'}]->
                  (target:Application {bundle_id: 'test.app.alpha'})
            RETURN count(r) AS n
            """,
            attacker_id=ATTACKER_BUNDLE_ID,
        )
        assert result.single()["n"] >= 1, "Expected CAN_INJECT_INTO (missing_library_validation) → test.app.alpha"

    def test_can_inject_into_dyld_insert(self, session):
        _seed_graph(session)
        from infer_injection import infer
        infer(session)

        # App A (hardened_runtime=false) should have dyld_insert edge
        result = session.run(
            """
            MATCH (:Application {bundle_id: $attacker_id})
                  -[r:CAN_INJECT_INTO {method: 'dyld_insert'}]->
                  (:Application {bundle_id: 'test.app.alpha'})
            RETURN count(r) AS n
            """,
            attacker_id=ATTACKER_BUNDLE_ID,
        )
        assert result.single()["n"] >= 1

    def test_can_inject_via_dyld_entitlement(self, session):
        _seed_graph(session)
        from infer_injection import infer
        infer(session)

        # App B has allow-dyld-environment-variables entitlement → dyld_insert_via_entitlement
        result = session.run(
            """
            MATCH (:Application {bundle_id: $attacker_id})
                  -[r:CAN_INJECT_INTO {method: 'dyld_insert_via_entitlement'}]->
                  (:Application {bundle_id: 'test.app.bravo'})
            RETURN count(r) AS n
            """,
            attacker_id=ATTACKER_BUNDLE_ID,
        )
        assert result.single()["n"] >= 1

    def test_inferred_flag_set(self, session):
        _seed_graph(session)
        from infer_injection import infer
        infer(session)

        result = session.run(
            """
            MATCH ()-[r:CAN_INJECT_INTO]->()
            WHERE r.inferred = true
            RETURN count(r) AS n
            """
        )
        assert result.single()["n"] > 0

    def test_attacker_node_created(self, session):
        _seed_graph(session)
        from infer_injection import infer
        infer(session)

        result = session.run(
            "MATCH (a:Application {bundle_id: $id}) RETURN count(a) AS n",
            id=ATTACKER_BUNDLE_ID,
        )
        assert result.single()["n"] == 1

    def test_idempotency(self, session):
        _seed_graph(session)
        from infer_injection import infer
        infer(session)
        n1 = session.run(
            "MATCH ()-[r:CAN_INJECT_INTO {inferred: true}]->() RETURN count(r) AS n"
        ).single()["n"]

        infer(session)
        n2 = session.run(
            "MATCH ()-[r:CAN_INJECT_INTO {inferred: true}]->() RETURN count(r) AS n"
        ).single()["n"]

        assert n1 == n2, f"Idempotency failed: {n1} → {n2} after second run"


class TestInferElectron:
    def test_child_inherits_tcc_for_electron_app(self, session):
        _seed_graph(session)
        from infer_injection import infer as infer_inj
        from infer_electron import infer
        infer_inj(session)  # ensure attacker node exists
        infer(session)

        result = session.run(
            """
            MATCH (:Application {bundle_id: $attacker_id})
                  -[r:CHILD_INHERITS_TCC {via: 'ELECTRON_RUN_AS_NODE'}]->
                  (:Application {bundle_id: 'test.app.bravo'})
            RETURN count(r) AS n
            """,
            attacker_id=ATTACKER_BUNDLE_ID,
        )
        assert result.single()["n"] >= 1

    def test_non_electron_app_not_targeted(self, session):
        _seed_graph(session)
        from infer_injection import infer as infer_inj
        from infer_electron import infer
        infer_inj(session)
        infer(session)

        # App A is not Electron — should NOT have CHILD_INHERITS_TCC
        result = session.run(
            """
            MATCH ()-[r:CHILD_INHERITS_TCC]->(:Application {bundle_id: 'test.app.alpha'})
            RETURN count(r) AS n
            """
        )
        assert result.single()["n"] == 0

    def test_idempotency(self, session):
        _seed_graph(session)
        from infer_injection import infer as infer_inj
        from infer_electron import infer
        infer_inj(session)
        infer(session)
        n1 = session.run(
            "MATCH ()-[r:CHILD_INHERITS_TCC {inferred: true}]->() RETURN count(r) AS n"
        ).single()["n"]
        infer(session)
        n2 = session.run(
            "MATCH ()-[r:CHILD_INHERITS_TCC {inferred: true}]->() RETURN count(r) AS n"
        ).single()["n"]
        assert n1 == n2


class TestInferAutomation:
    def test_can_send_apple_event(self, session):
        _seed_graph(session)
        from infer_injection import infer as infer_inj
        from infer_automation import infer
        infer_inj(session)
        infer(session)

        # App C has AppleEvents grant → can automate App A (which has FDA) and App B (Screen Recording)
        result = session.run(
            """
            MATCH (:Application {bundle_id: 'test.app.charlie'})
                  -[r:CAN_SEND_APPLE_EVENT {inferred: true}]->
                  (:Application {bundle_id: 'test.app.alpha'})
            RETURN count(r) AS n
            """
        )
        assert result.single()["n"] >= 1

    def test_idempotency(self, session):
        _seed_graph(session)
        from infer_injection import infer as infer_inj
        from infer_automation import infer
        infer_inj(session)
        infer(session)
        n1 = session.run(
            "MATCH ()-[r:CAN_SEND_APPLE_EVENT {inferred: true}]->() RETURN count(r) AS n"
        ).single()["n"]
        infer(session)
        n2 = session.run(
            "MATCH ()-[r:CAN_SEND_APPLE_EVENT {inferred: true}]->() RETURN count(r) AS n"
        ).single()["n"]
        assert n1 == n2
