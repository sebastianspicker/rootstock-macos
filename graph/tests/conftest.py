"""
conftest.py — Shared pytest fixtures for Rootstock graph tests.

Provides:
  - Neo4j connection env vars (NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
  - neo4j_driver: session-scoped driver that skips if Neo4j is unavailable
  - cleanup_test_nodes(): utility to remove test data by scan_id
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure graph/ is on the import path
sys.path.insert(0, str(Path(__file__).parent.parent))

# ── Shared constants ─────────────────────────────────────────────────────────

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "rootstock")


# ── Neo4j driver fixture (session-scoped) ────────────────────────────────────


@pytest.fixture(scope="session")
def neo4j_driver():
    """
    Session-scoped Neo4j driver. Skips all tests if Neo4j is unavailable.
    """
    try:
        from neo4j import GraphDatabase
        from neo4j.exceptions import ServiceUnavailable, AuthError
    except ImportError:
        pytest.skip("neo4j driver not installed")

    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()
    except (ServiceUnavailable, ConnectionRefusedError):
        pytest.skip(f"Neo4j not available at {NEO4J_URI}")
    except AuthError:
        pytest.skip("Neo4j auth failed — check NEO4J_USER / NEO4J_PASSWORD")

    with driver.session() as session:
        from setup_schema import apply_schema

        apply_schema(session)

    yield driver
    driver.close()


def cleanup_test_nodes(session, scan_id: str) -> None:
    """Remove the test subgraph for ``scan_id`` without touching unrelated data.

    The cleanup flow is intentionally conservative:
    1. Capture the ids of nodes within two hops of the test applications.
    2. Delete the test applications themselves by ``scan_id``.
    3. Delete only captured nodes whose remaining relationships stay within
       the captured set.

    This avoids global orphan sweeps, which are unsafe against shared Neo4j
    databases that may contain unrelated but disconnected nodes.
    """
    result = session.run(
        """
        MATCH (a:Application {scan_id: $scan_id})
        OPTIONAL MATCH (a)-[*1..2]-(n)
        RETURN collect(DISTINCT elementId(a)) + collect(DISTINCT elementId(n)) AS node_ids
        """,
        scan_id=scan_id,
    )
    record = result.single()
    node_ids = list(dict.fromkeys(record["node_ids"] if record else []))

    session.run(
        "MATCH (a:Application {scan_id: $scan_id}) DETACH DELETE a",
        scan_id=scan_id,
    )

    if not node_ids:
        return

    session.run(
        """
        UNWIND $node_ids AS node_id
        MATCH (n)
        WHERE elementId(n) = node_id
          AND NOT EXISTS {
              MATCH (n)--(outside)
              WHERE NOT elementId(outside) IN $node_ids
          }
        WITH collect(n) AS doomed
        FOREACH (n IN doomed | DETACH DELETE n)
        """,
        node_ids=node_ids,
    )
