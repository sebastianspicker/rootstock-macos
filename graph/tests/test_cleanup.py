"""
test_cleanup.py — Regression tests for graph test cleanup safety.

Requires a running Neo4j instance. Tests are skipped if Neo4j is unavailable.
"""

from __future__ import annotations

import pytest

from conftest import cleanup_test_nodes

TEST_SCAN_ID = "test-cleanup-00000000-0000-0000-0000-000000000004"
UNRELATED_TITLE = "keep-unrelated-orphan"


@pytest.fixture(scope="module")
def session(neo4j_driver):
    """Module-scoped Neo4j session with targeted cleanup."""
    with neo4j_driver.session() as s:
        yield s
    with neo4j_driver.session() as s:
        cleanup_test_nodes(s, TEST_SCAN_ID)
        s.run(
            "MATCH (r:Recommendation {title: $title}) DETACH DELETE r",
            title=UNRELATED_TITLE,
        )


def test_cleanup_only_removes_test_subgraph(session):
    session.run(
        """
        CREATE (:Recommendation {title: $title})

        MERGE (app:Application {bundle_id: 'com.rootstock.cleanup.test'})
        SET app.name = 'Cleanup Test App',
            app.path = '/Applications/CleanupTest.app',
            app.scan_id = $scan_id

        MERGE (perm:TCC_Permission {service: 'kTCCServiceCleanupTest'})
        SET perm.display_name = 'Cleanup Test Permission'

        MERGE (launch:LaunchItem {label: 'com.rootstock.cleanup.test.launch'})
        SET launch.path = '/Library/LaunchDaemons/com.rootstock.cleanup.test.plist'

        MERGE (user:User {name: 'cleanup-test-user'})

        MERGE (app)-[:HAS_TCC_GRANT {allowed: true, scope: 'user', scan_id: $scan_id}]->(perm)
        MERGE (app)-[:PERSISTS_VIA]->(launch)
        MERGE (launch)-[:RUNS_AS]->(user)
        """,
        scan_id=TEST_SCAN_ID,
        title=UNRELATED_TITLE,
    )

    cleanup_test_nodes(session, TEST_SCAN_ID)

    counts = session.run(
        """
        RETURN
            COUNT { MATCH (:Recommendation {title: $title}) } > 0 AS unrelated_exists,
            COUNT { MATCH (:Application {bundle_id: 'com.rootstock.cleanup.test'}) } > 0 AS app_exists,
            COUNT { MATCH (:TCC_Permission {service: 'kTCCServiceCleanupTest'}) } > 0 AS perm_exists,
            COUNT { MATCH (:LaunchItem {label: 'com.rootstock.cleanup.test.launch'}) } > 0 AS launch_exists,
            COUNT { MATCH (:User {name: 'cleanup-test-user'}) } > 0 AS user_exists
        """,
        title=UNRELATED_TITLE,
    ).single()

    assert counts["unrelated_exists"] is True
    assert counts["app_exists"] is False
    assert counts["perm_exists"] is False
    assert counts["launch_exists"] is False
    assert counts["user_exists"] is False
