"""Characterize the public HTTP route table and its bearer-token boundary."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from rootstock_graph import api


TOKEN = "t" * 32

EXPECTED_ROUTES = [
    (("GET",), "/"),
    (("GET",), "/api/graph"),
    (("GET",), "/api/owned"),
    (("GET",), "/api/queries"),
    (("POST",), "/api/clear-owned"),
    (("POST",), "/api/cypher"),
    (("POST",), "/api/mark-owned"),
    (("POST",), "/api/queries/{query_id}/run"),
    (("POST",), "/api/report"),
    (("POST",), "/api/tier-classify"),
]


class UnusedDriver:
    """Fail the test if an unauthenticated request reaches Neo4j."""

    def session(self, **_kwargs: object) -> None:
        raise AssertionError("unauthenticated request opened a Neo4j session")


@pytest.fixture
def unauthenticated_client() -> Iterator[TestClient]:
    api.app.state.api_token = TOKEN
    api.app.state.writer_driver = UnusedDriver()
    api.app.state.read_driver = UnusedDriver()
    yield TestClient(api.app)


def _route_table() -> list[tuple[tuple[str, ...], str]]:
    """Read the effective route table, including routes from included routers."""
    paths = api.app.openapi()["paths"]
    return sorted(
        (tuple(sorted(method.upper() for method in operations)), path)
        for path, operations in paths.items()
    )


def test_route_table_is_stable() -> None:
    assert _route_table() == EXPECTED_ROUTES


@pytest.mark.parametrize(
    ("methods", "path"),
    [route for route in EXPECTED_ROUTES if route[1].startswith("/api/")],
)
@pytest.mark.parametrize("authorization", [None, "Bearer wrong-token", TOKEN])
def test_every_api_route_requires_bearer_token(
    unauthenticated_client: TestClient,
    methods: tuple[str, ...],
    path: str,
    authorization: str | None,
) -> None:
    headers = {"Authorization": authorization} if authorization else {}
    url = path.replace("{query_id}", "example")
    for method in methods:
        response = unauthenticated_client.request(method, url, headers=headers, json={})
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
