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

AUTH_HEADERS = {"Authorization": "Bearer test-token"}


class AuthenticatedClient:
    def __init__(self, client):
        self.raw = client

    def get(self, url, **kwargs):
        kwargs.setdefault("headers", AUTH_HEADERS)
        return self.raw.get(url, **kwargs)

    def post(self, url, **kwargs):
        kwargs.setdefault("headers", AUTH_HEADERS)
        return self.raw.post(url, **kwargs)


@pytest.fixture(scope="module")
def raw_client():
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
    app.state.api_token = "test-token"

    from fastapi.testclient import TestClient

    # Patch GraphDatabase.driver so the lifespan handler uses our mock
    # instead of attempting a real Neo4j connection.
    with patch("server.GraphDatabase") as mock_gdb:
        mock_gdb.driver.return_value = mock_driver
        with TestClient(app, raise_server_exceptions=False) as tc:
            yield tc


@pytest.fixture
def client(raw_client):
    return AuthenticatedClient(raw_client)


class TestRouteSurface:
    def test_public_viewer_api_routes_are_locked(self):
        """Only the viewer API routes should be exposed as FastAPI app routes."""
        from fastapi.routing import APIRoute
        from server import app

        expected_routes = {
            ("GET", "/"),
            ("GET", "/api/queries"),
            ("POST", "/api/queries/{query_id}/run"),
            ("GET", "/api/graph"),
            ("POST", "/api/mark-owned"),
            ("POST", "/api/clear-owned"),
            ("GET", "/api/owned"),
            ("POST", "/api/tier-classify"),
            ("POST", "/api/cypher"),
        }
        actual_routes = {
            (method, route.path)
            for route in app.routes
            if isinstance(route, APIRoute)
            for method in route.methods
            if method in {"GET", "POST"}
        }

        assert actual_routes == expected_routes


class TestAuthAndBindGuards:
    def test_api_requires_bearer_token(self, raw_client):
        response = raw_client.get("/api/queries")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_api_accepts_valid_bearer_token(self, raw_client):
        response = raw_client.get("/api/queries", headers=AUTH_HEADERS)
        assert response.status_code == 200

    def test_viewer_route_does_not_embed_live_graph(self, raw_client):
        response = raw_client.get("/")
        assert response.status_code == 200
        assert '"nodes": []' in response.text
        assert '"edges": []' in response.text

    def test_non_loopback_bind_requires_explicit_remote_flag(self):
        from server import _validate_bind_host

        _validate_bind_host("127.0.0.1", allow_remote=False)
        _validate_bind_host("::1", allow_remote=False)
        _validate_bind_host("0.0.0.0", allow_remote=True)
        with pytest.raises(ValueError):
            _validate_bind_host("0.0.0.0", allow_remote=False)


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

    def test_graph_gets_deterministic_positions(self, client):
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

        with patch("server._get_hostname", return_value="cached-host"), patch(
            "server.build_opengraph",
            side_effect=lambda *_args, **_kwargs: copy.deepcopy(graph_payload),
        ):
            first = client.get("/api/graph")
            second = client.get("/api/graph")

        assert first.status_code == 200
        assert second.status_code == 200
        for node in first.json()["graph"]["nodes"]:
            assert isinstance(node["x"], int | float)
            assert isinstance(node["y"], int | float)
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
        assert data["truncated"] is False

    def test_dbms_procedure_rejected(self, client):
        response = client.post("/api/cypher", json={
            "cypher": "CALL dbms.listConfig()"
        })
        assert response.status_code == 403

    def test_oversized_query_rejected(self, client):
        response = client.post("/api/cypher", json={
            "cypher": "MATCH (n) RETURN n // " + ("x" * 10000)
        })
        assert response.status_code == 413

    def test_rows_are_limited_and_truncated_flag_is_returned(self, raw_client):
        from server import app, get_read_session

        session = MagicMock()
        session.run.return_value = [{"n": i} for i in range(1005)]

        def override_session():
            yield session

        app.dependency_overrides[get_read_session] = override_session
        try:
            response = raw_client.post(
                "/api/cypher",
                headers=AUTH_HEADERS,
                json={"cypher": "MATCH (n) RETURN n"},
            )
        finally:
            app.dependency_overrides.clear()

        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 1000
        assert data["truncated"] is True

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
