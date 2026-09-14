"""Export query bounds, endpoint identity parity, and sanitized API failures."""

from unittest.mock import patch

import pytest
from fastapi import HTTPException
from neo4j import Query
from neo4j.exceptions import ServiceUnavailable

from rootstock_graph.api_support import routes
from rootstock_graph.constants import NODE_KEY_PROPERTY
from rootstock_graph.reporting import opengraph_export as export


class Session:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def run(self, query, **params):
        self.calls.append((query, params))
        return iter(self.rows[: params.get("maximum_records", len(self.rows))])


def test_bounded_nodes_query_limit_and_timeout():
    session = Session([{"n": {"name": str(i)}, "labels": ["User"]} for i in range(10)])
    assert len(export.export_nodes(session, "synthetic", 3)) == 3
    query, params = session.calls[0]
    assert isinstance(query, Query) and query.timeout == 5
    assert "LIMIT $maximum_records" in query.text
    assert params["maximum_records"] == 3


def test_unrestricted_export_stays_unrestricted():
    session = Session([{"n": {"name": str(i)}, "labels": ["User"]} for i in range(20)])
    assert len(export.export_nodes(session, "synthetic")) == 20
    query, params = session.calls[0]
    assert isinstance(query, str) and "LIMIT" not in query
    assert "maximum_records" not in params


@pytest.mark.parametrize("label", list(export.NODE_TYPE_MAP))
@pytest.mark.parametrize("value", [None, "", "value"])
def test_endpoint_projection_preserves_identity(label, value):
    props = {key: value for key in NODE_KEY_PROPERTY.values()}
    props.update({"app_key": value, "computer_key": value, "profile_key": value, "kind": value})
    props["large_unused_evidence"] = "unused" * 100
    for candidate in ({}, props):
        projected = [
            [key, item] for key, item in candidate.items() if key in export.IDENTITY_PROPERTIES
        ]
        decoded = export._endpoint_properties(projected)
        assert export._node_key(label, decoded) == export._node_key(label, candidate)
        assert ("name" in decoded) == ("name" in candidate)


def test_edges_project_identity_only_and_keep_relationship_properties():
    record = {
        "src_labels": ["Application"],
        "src": [["bundle_id", "app"], ["app_key", "full-key"]],
        "tgt_labels": ["Keychain_Item"],
        "tgt": [["label", "item"], ["kind", None]],
        "rel": {"evidence": "all relationship evidence", "optional": None},
        "rel_type": "CAN_READ_KEYCHAIN",
    }
    session = Session([record])
    edge = export.export_edges(session, "synthetic", 10)[0]
    query, params = session.calls[0]
    assert query.timeout == 5 and "LIMIT $maximum_records" in query.text
    assert "keys(s)" in query.text and "keys(t)" in query.text
    assert params["identity_properties"] == export.IDENTITY_PROPERTIES
    assert edge["properties"]["evidence"] == record["rel"]["evidence"]
    assert edge["properties"]["optional"] is None
    assert edge["target"] == export.make_node_id("synthetic", "Keychain_Item", "item-None")


def test_node_overflow_does_not_query_edges():
    session = Session([{"n": {"name": str(i)}, "labels": ["User"]} for i in range(4)])
    data = export.build_opengraph(session, "synthetic", maximum_nodes=3, maximum_edges=5)
    assert len(session.calls) == 1
    assert len(data["graph"]["nodes"]) == 3
    with (
        patch.object(routes, "_get_hostname", return_value="synthetic"),
        patch.object(routes, "INTERACTIVE_GRAPH_MAX_NODES", 2),
    ):
        with pytest.raises(HTTPException) as error:
            routes._build_live_graph(session)
    assert error.value.status_code == 413
    assert len(session.calls) == 2


def test_database_failure_is_sanitized():
    with patch.object(
        routes, "_get_hostname", side_effect=ServiceUnavailable("secret connection details")
    ):
        with pytest.raises(HTTPException) as error:
            routes._build_live_graph(None)
    assert error.value.status_code == 503
    assert error.value.detail == "Graph retrieval failed"
