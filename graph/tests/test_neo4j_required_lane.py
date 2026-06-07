"""Tests for the required Neo4j verification lane behavior."""

from __future__ import annotations

import pytest

import conftest as graph_conftest


def test_required_neo4j_lane_fails_instead_of_skipping(monkeypatch):
    monkeypatch.setenv("ROOTSTOCK_REQUIRE_NEO4J", "1")

    with pytest.raises(pytest.fail.Exception, match="Required Neo4j verification"):
        graph_conftest._skip_or_fail_neo4j_unavailable("missing password")


def test_default_neo4j_lane_keeps_local_skip(monkeypatch):
    monkeypatch.delenv("ROOTSTOCK_REQUIRE_NEO4J", raising=False)

    with pytest.raises(pytest.skip.Exception, match="missing password"):
        graph_conftest._skip_or_fail_neo4j_unavailable("missing password")
