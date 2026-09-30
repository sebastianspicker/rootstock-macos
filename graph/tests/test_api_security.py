from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from neo4j import READ_ACCESS
from neo4j.exceptions import ServiceUnavailable

from rootstock_graph import api
from rootstock_graph.api_support import dependencies


TOKEN = "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}
VERIFY_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify"


class FakeResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows

    def __iter__(self) -> Iterator[dict[str, object]]:
        return iter(self.rows)

    def single(self) -> dict[str, object] | None:
        return self.rows[0] if self.rows else None


class FakeSession:
    def __init__(self) -> None:
        self.rows = [{"n": 1, "value": 1}]
        self.failure: Exception | None = None
        self.queries: list[object] = []
        self.begin_transactions = 0

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def begin_transaction(self) -> "FakeSession":
        self.begin_transactions += 1
        return self

    def run(self, cypher: object, *_args: object, **_kwargs: object) -> FakeResult:
        self.queries.append(cypher)
        if self.failure:
            raise self.failure
        return FakeResult(self.rows)


class FakeDriver:
    def __init__(self, session: FakeSession, name: str) -> None:
        self.session_instance = session
        self.name = name
        self.access_modes: list[object] = []
        self.closed = False
        self.verify_calls = 0

    def session(self, **kwargs: object) -> FakeSession:
        self.access_modes.append(kwargs.get("default_access_mode"))
        return self.session_instance

    def verify_connectivity(self) -> None:
        self.verify_calls += 1

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def api_client() -> Iterator[tuple[TestClient, FakeDriver, FakeDriver, FakeSession]]:
    writer_session = FakeSession()
    read_session = FakeSession()
    writer_driver = FakeDriver(writer_session, "writer")
    read_driver = FakeDriver(read_session, "reader")
    api.app.state.api_token = TOKEN
    api.app.state.writer_driver = writer_driver
    api.app.state.read_driver = read_driver
    client = TestClient(api.app)
    yield client, writer_driver, read_driver, read_session
    api.app.dependency_overrides.clear()


def test_api_requires_bearer_token_and_sets_security_headers(api_client) -> None:
    client, _writer, _reader, _session = api_client
    response = client.get("/api/queries")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers["content-security-policy"]


def test_api_cors_allows_loopback_only(api_client) -> None:
    client, _writer, _reader, _session = api_client
    allowed = client.options(
        "/api/cypher",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
        },
    )
    denied = client.options(
        "/api/cypher",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-origin" not in denied.headers


@pytest.mark.parametrize(
    "cypher",
    [
        "CREATE (n)",
        "CALL db.labels()",
        "MATCH (n) RETURN n; MATCH (m) RETURN m",
    ],
)
def test_api_rejects_write_procedure_and_multistatement_cypher(api_client, cypher: str) -> None:
    client, _writer, _reader, session = api_client
    response = client.post("/api/cypher", headers=AUTH, json={"cypher": cypher})
    assert response.status_code == 403
    assert not session.queries


def test_api_bounds_cypher_size_rows_timeout_and_read_access(api_client) -> None:
    client, writer_driver, read_driver, session = api_client
    session.rows = [{"row": index} for index in range(dependencies.MAX_ADHOC_CYPHER_ROWS + 2)]
    response = client.post("/api/cypher", headers=AUTH, json={"cypher": "MATCH (n) RETURN n"})
    assert response.status_code == 200
    assert response.json()["count"] == dependencies.MAX_ADHOC_CYPHER_ROWS
    assert response.json()["truncated"] is True
    assert writer_driver.access_modes == []
    assert read_driver.access_modes == [READ_ACCESS]
    assert session.queries[0].timeout == dependencies.ADHOC_CYPHER_TIMEOUT_SECONDS

    too_long = client.post(
        "/api/cypher",
        headers=AUTH,
        json={"cypher": "M" * (dependencies.MAX_ADHOC_CYPHER_LENGTH + 1)},
    )
    assert too_long.status_code == 413


def test_api_sanitizes_neo4j_driver_failures(api_client) -> None:
    client, _writer, _reader, session = api_client
    session.failure = ServiceUnavailable("bolt://secret-user:secret-password@host")
    response = client.post("/api/cypher", headers=AUTH, json={"cypher": "MATCH (n) RETURN n"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Query execution failed"}
    assert "secret-password" not in response.text


def test_mark_owned_accepts_one_selector_in_one_transaction(api_client) -> None:
    client, writer_driver, read_driver, _read_session = api_client
    rejected = client.post(
        "/api/mark-owned",
        headers=AUTH,
        json={"bundle_ids": ["one"], "usernames": ["two"]},
    )
    assert rejected.status_code == 422
    assert writer_driver.session_instance.begin_transactions == 0

    accepted = client.post(
        "/api/mark-owned",
        headers=AUTH,
        json={"bundle_ids": ["one"]},
    )
    assert accepted.status_code == 200
    assert accepted.json()["marked"] == 1
    assert writer_driver.session_instance.begin_transactions == 1
    assert read_driver.access_modes == []


@pytest.mark.anyio
async def test_lifespan_uses_and_closes_distinct_principal_drivers(monkeypatch) -> None:
    writer_driver = FakeDriver(FakeSession(), "writer")
    read_driver = FakeDriver(FakeSession(), "reader")
    created: list[tuple[str, str]] = []

    def create_driver(_uri: str, auth: tuple[str, str]) -> FakeDriver:
        created.append(auth)
        return writer_driver if auth[0] == "writer" else read_driver

    monkeypatch.setattr(api.GraphDatabase, "driver", create_driver)
    api.app.state.neo4j_uri = "bolt://localhost:7687"
    api.app.state.neo4j_user = "writer"
    api.app.state.neo4j_password = "writer-password"
    api.app.state.neo4j_read_user = "reader"
    api.app.state.neo4j_read_password = "reader-password"

    async with api.lifespan(api.app):
        assert api.app.state.writer_driver is writer_driver
        assert api.app.state.read_driver is read_driver
        assert created == [("writer", "writer-password"), ("reader", "reader-password")]
        assert writer_driver.verify_calls == read_driver.verify_calls == 1

    assert writer_driver.closed is True
    assert read_driver.closed is True


@pytest.mark.parametrize("missing", ["NEO4J_READ_USER", "NEO4J_READ_PASSWORD"])
def test_api_startup_fails_closed_without_read_credentials(
    monkeypatch, capsys, missing: str
) -> None:
    monkeypatch.setenv("NEO4J_PASSWORD", "writer-password")
    monkeypatch.setenv("ROOTSTOCK_API_TOKEN", TOKEN)
    monkeypatch.setenv("NEO4J_READ_USER", "reader")
    monkeypatch.setenv("NEO4J_READ_PASSWORD", "reader-password")
    monkeypatch.delenv(missing)

    monkeypatch.setattr(sys, "argv", ["rootstock-graph-api", "--neo4j-user", "writer"])
    assert api.main() == 1
    assert missing in capsys.readouterr().err


def test_api_startup_rejects_writer_as_read_principal(monkeypatch, capsys) -> None:
    monkeypatch.setenv("NEO4J_PASSWORD", "writer-password")
    monkeypatch.setenv("ROOTSTOCK_API_TOKEN", TOKEN)
    monkeypatch.setenv("NEO4J_READ_USER", "writer")
    monkeypatch.setenv("NEO4J_READ_PASSWORD", "reader-password")

    monkeypatch.setattr(sys, "argv", ["rootstock-graph-api", "--neo4j-user", "writer"])
    assert api.main() == 1
    assert "must differ" in capsys.readouterr().err


def test_api_startup_rejects_non_loopback_bind_before_reading_credentials(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(sys, "argv", ["rootstock-graph-api", "--host", "0.0.0.0"])

    assert api.main() == 1
    assert "loopback" in capsys.readouterr().err


def test_api_rejects_invalid_bearer_token(api_client) -> None:
    client, _writer, _reader, _session = api_client

    response = client.get("/api/queries", headers={"Authorization": "Bearer short"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing or invalid bearer token"}


@pytest.mark.parametrize("authorization", ["Basic credentials", "Bearer"])
def test_api_rejects_malformed_authorization_before_body_validation(
    api_client, authorization: str
) -> None:
    client, _writer, _reader, _session = api_client

    response = client.post(
        "/api/cypher",
        headers={"Authorization": authorization},
        content="not-json",
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing or invalid bearer token"}


def test_neo4j_lane_uses_one_resolved_uri_for_check_and_api() -> None:
    source = VERIFY_SCRIPT.read_text(encoding="utf-8")
    assert "neo4j_uri=${NEO4J_URI:-bolt://localhost:7687}" in source
    assert '--uri "$neo4j_uri"' in source
    assert '--neo4j "$neo4j_uri"' in source
