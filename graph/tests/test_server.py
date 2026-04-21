"""
test_server.py — Tests for the Rootstock REST API server.

Uses FastAPI's TestClient for synchronous HTTP testing without
requiring a running Neo4j instance (tests mock the Neo4j session).

Usage:
    pytest graph/tests/test_server.py -v
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure graph/ is on the import path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="module")
def client():
    """Create a FastAPI TestClient with a mocked Neo4j driver."""
    from server import app

    # Mock the Neo4j driver on app.state before creating the TestClient
    mock_driver = MagicMock()
    mock_session = MagicMock()

    # Default: session.run returns empty result
    mock_result = MagicMock()
    mock_result.__iter__ = lambda self: iter([])
    mock_result.single.return_value = {"n": 0}
    mock_session.run.return_value = mock_result
    mock_driver.session.return_value.__enter__ = lambda self: mock_session
    mock_driver.session.return_value.__exit__ = lambda self, *a: None

    app.state.neo4j_uri = "bolt://localhost:7687"
    app.state.neo4j_user = "neo4j"
    app.state.neo4j_password = "test"

    from fastapi.testclient import TestClient

    # Patch GraphDatabase.driver so the lifespan handler uses our mock
    # instead of attempting a real Neo4j connection.
    with patch("server.GraphDatabase") as mock_gdb:
        mock_gdb.driver.return_value = mock_driver
        with TestClient(app, raise_server_exceptions=False) as tc:
            yield tc


class TestQueryEndpoints:
    def test_list_queries(self, client):
        """GET /api/queries should return a list of query descriptors."""
        response = client.get("/api/queries")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 101
        # Each query should have required fields
        for q in data:
            assert "id" in q
            assert "name" in q
            assert "category" in q
            assert "severity" in q

    def test_list_queries_has_101(self, client):
        """Should discover exactly 101 queries."""
        response = client.get("/api/queries")
        assert len(response.json()) == 101

    def test_query_79_in_list(self, client):
        """Query 79 (stale keytab detection) should appear in the list."""
        response = client.get("/api/queries")
        ids = [q["id"] for q in response.json()]
        assert "79" in ids


class TestStaticEndpoints:
    def test_api_queries_structure(self, client):
        """Each query descriptor should have the expected fields."""
        response = client.get("/api/queries")
        if response.status_code == 200 and response.json():
            q = response.json()[0]
            expected_keys = {"id", "filename", "name", "purpose", "category", "severity", "parameters"}
            assert expected_keys.issubset(set(q.keys()))

    def test_graph_layout_is_cached_for_identical_payloads(self, client):
        from server import _LAYOUT_CACHE, _LAYOUT_CACHE_ORDER

        _LAYOUT_CACHE.clear()
        _LAYOUT_CACHE_ORDER.clear()

        graph_payload = {
            "graph": {
                "nodes": [
                    {"id": "n1", "kind": "rs_Application", "label": "App One"},
                    {"id": "n2", "kind": "rs_TCCPermission", "label": "FDA"},
                ],
                "edges": [
                    {"source": "n1", "target": "n2", "kind": "rs_HasTCCGrant"},
                ],
            }
        }

        def fake_layout(nodes, _edges, iterations):
            for index, node in enumerate(nodes):
                node["x"] = float(index)
                node["y"] = float(iterations + index)

        with patch("server._get_hostname", return_value="cached-host"), patch(
            "server.build_opengraph",
            side_effect=lambda *_args, **_kwargs: copy.deepcopy(graph_payload),
        ), patch("server.compute_layout", side_effect=fake_layout) as mock_layout:
            first = client.get("/api/graph")
            second = client.get("/api/graph")

        assert first.status_code == 200
        assert second.status_code == 200
        assert mock_layout.call_count == 1
        assert first.json()["graph"]["nodes"] == second.json()["graph"]["nodes"]


class TestOwnedEndpoints:
    def test_mark_owned_no_match(self, client):
        """POST /api/mark-owned with nonexistent bundle_id should return 404."""
        response = client.post("/api/mark-owned", json={"bundle_ids": ["com.fake.app"]})
        assert response.status_code == 404

    def test_clear_owned_requires_target(self, client):
        """POST /api/clear-owned without specifying target should return 400."""
        response = client.post("/api/clear-owned", json={})
        assert response.status_code == 400


class TestTierEndpoint:
    def test_tier_classify_returns_counts(self, client):
        """POST /api/tier-classify should return tier counts."""
        response = client.post("/api/tier-classify")
        assert response.status_code == 200
        data = response.json()
        assert "tier0" in data
        assert "tier1" in data
        assert "tier2" in data
        assert "total" in data


class TestCypherEndpoint:
    def test_read_query_succeeds(self, client):
        """POST /api/cypher with a MATCH query should return 200."""
        response = client.post("/api/cypher", json={
            "cypher": "MATCH (n) RETURN n LIMIT 1"
        })
        assert response.status_code == 200
        data = response.json()
        assert "columns" in data
        assert "rows" in data
        assert "count" in data

    def test_write_query_rejected_create(self, client):
        """POST /api/cypher with CREATE should return 403."""
        response = client.post("/api/cypher", json={
            "cypher": "CREATE (n:Test {name: 'bad'})"
        })
        assert response.status_code == 403

    def test_write_query_rejected_merge(self, client):
        """POST /api/cypher with MERGE should return 403."""
        response = client.post("/api/cypher", json={
            "cypher": "MERGE (n:Test {name: 'bad'})"
        })
        assert response.status_code == 403

    def test_write_query_rejected_delete(self, client):
        """POST /api/cypher with DELETE should return 403."""
        response = client.post("/api/cypher", json={
            "cypher": "MATCH (n) DELETE n"
        })
        assert response.status_code == 403

    def test_write_query_rejected_set(self, client):
        """POST /api/cypher with SET should return 403."""
        response = client.post("/api/cypher", json={
            "cypher": "MATCH (n) SET n.name = 'bad'"
        })
        assert response.status_code == 403

    def test_write_query_rejected_drop(self, client):
        """POST /api/cypher with DROP should return 403."""
        response = client.post("/api/cypher", json={
            "cypher": "DROP INDEX my_index"
        })
        assert response.status_code == 403

    def test_write_query_rejected_case_insensitive(self, client):
        """Write detection should be case-insensitive."""
        response = client.post("/api/cypher", json={
            "cypher": "create (n:Test)"
        })
        assert response.status_code == 403

    def test_write_in_string_literal_allowed(self, client):
        """'CREATE' inside a string literal should NOT be rejected."""
        response = client.post("/api/cypher", json={
            "cypher": "MATCH (n) WHERE n.name = 'CREATE something' RETURN n"
        })
        assert response.status_code == 200

    def test_empty_query(self, client):
        """Empty cypher should still go through (server or Neo4j handles it)."""
        response = client.post("/api/cypher", json={"cypher": ""})
        # Empty query likely fails at Neo4j level with 400
        assert response.status_code in (200, 400)
