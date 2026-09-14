from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from rootstock_graph import api
from rootstock_graph.ingestion import import_family_export, import_scan
from rootstock_graph.paths import package_resource_dir
from rootstock_graph.reporting import query_runner
from rootstock_graph.reporting.viewer import render_viewer_html
from rootstock_graph.server_validation import (
    matches_api_token,
    validate_api_cypher,
    validate_bind_host,
    validate_neo4j_uri,
)


def test_public_package_domains_import_without_live_neo4j() -> None:
    modules = (
        "rootstock_graph.models",
        "rootstock_graph.neo4j",
        "rootstock_graph.api",
        "rootstock_graph.ingestion.import_scan",
        "rootstock_graph.inference.infer",
        "rootstock_graph.reporting.report",
        "rootstock_graph.vulnerability.cve_enrichment",
    )
    for module in modules:
        assert importlib.import_module(module)


def test_package_resources_supply_queries_and_viewer_runtime() -> None:
    queries = query_runner.discover_queries()
    assert len(queries) == 103
    assert query_runner.find_query(queries, "01")["filename"] == ("01-injectable-fda-apps.cypher")

    html = render_viewer_html(
        {"graph": {"nodes": [], "edges": []}}, title="Packaged", mode="static"
    )
    assert "RootstockViewer.mount" in html
    assert "{{VIEWER_JS}}" not in html


def test_api_keeps_loopback_token_and_read_only_cypher_contracts() -> None:
    assert (
        api.MAX_ADHOC_CYPHER_LENGTH,
        api.MAX_ADHOC_CYPHER_ROWS,
        api.ADHOC_CYPHER_TIMEOUT_SECONDS,
    ) == (10_000, 1_000, 5.0)
    validate_bind_host("localhost")
    validate_bind_host("127.0.0.1")
    validate_neo4j_uri("bolt://localhost:7687")
    assert matches_api_token("Bearer " + "t" * 32, "t" * 32)
    assert validate_api_cypher("MATCH (n) RETURN n") is None

    with pytest.raises(ValueError, match="loopback"):
        validate_bind_host("0.0.0.0")
    with pytest.raises(ValueError, match="non-loopback"):
        validate_neo4j_uri("bolt://neo4j.example.test:7687")
    assert validate_api_cypher("CALL db.labels()") == (
        "Procedures are not allowed through the viewer API"
    )


def test_api_cli_keeps_loopback_default_and_port_flag() -> None:
    args = api._build_parser().parse_args(["--port", "8123"])
    assert (args.host, args.port, args.neo4j) == (
        "127.0.0.1",
        8123,
        "bolt://localhost:7687",
    )


def test_importer_cli_keeps_input_and_neo4j_flags() -> None:
    args = import_scan._build_parser().parse_args(
        [
            "--input",
            "scan.json",
            "--neo4j",
            "bolt://localhost:7688",
            "--neo4j-user",
            "operator",
            "--verbose",
        ]
    )
    assert (args.input, args.uri, args.neo4j_user, args.verbose) == (
        "scan.json",
        "bolt://localhost:7688",
        "operator",
        True,
    )
    assert query_runner._build_parser().parse_args(["--list"]).list


def test_family_export_validation_and_neo4j_merge_identity_are_preserved() -> None:
    export = import_family_export.validate_export(
        {
            "schema_version": 1,
            "source": "rootstock-red",
            "generated_at": "2026-08-27T00:00:00Z",
            "scope_name": "test-host",
            "scan_profile": "test",
            "node_types": ["Host", "Finding"],
            "edge_vocabulary": ["HAS_FINDING"],
            "edge_types": ["HAS_FINDING"],
            "nodes": [
                {"id": "host-1", "type": "Host", "name": "mac"},
                {"id": "finding-1", "type": "Finding", "details": {"skip": True}},
            ],
            "edges": [{"from": "host-1", "to": "finding-1", "type": "HAS_FINDING"}],
        }
    )

    class Session:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict]] = []

        def run(self, cypher: str, **params: object) -> None:
            self.calls.append((cypher, params))

    session = Session()
    assert import_family_export.import_family_export(session, export) == {
        "nodes": 2,
        "edges": 1,
        "Host": 1,
        "Finding": 1,
    }
    assert "MERGE (n:`Host` {id: row.id})" in session.calls[0][0]
    assert "MERGE (a)-[r:`HAS_FINDING`]->(b)" in session.calls[-1][0]
    finding_props = import_family_export.build_node_records(export)["Finding"][0]["props"]
    assert "details" not in finding_props


def test_family_export_accepts_contract_permitted_sparse_extensions() -> None:
    export = import_family_export.validate_export(
        {
            "schema_version": 1,
            "source": "rootstock-blue",
            "generated_at": "2026-08-27T00:00:00Z",
            "scope_name": "test-host",
            "scan_profile": "test",
            "node_types": ["Host"],
            "edge_vocabulary": ["HAS_FINDING"],
            "nodes": [
                {
                    "id": "host-1",
                    "type": "Host",
                    "extension": {"nested": ["preserved", 1, True]},
                }
            ],
            "edges": [],
            "top_level_extension": {"producer": "rootstock-blue"},
        }
    )
    assert export.nodes[0]["extension"] == {"nested": ["preserved", 1, True]}


def test_packaged_family_schema_keeps_the_canonical_identity() -> None:
    schema = json.loads(
        package_resource_dir("contracts")
        .joinpath("family-open-export", "v1", "schema.json")
        .read_text(encoding="utf-8")
    )
    assert schema["$id"] == import_family_export.FAMILY_EXPORT_SCHEMA_ID


def test_packaged_cve_schema_is_byte_identical_to_the_canonical_contract() -> None:
    root = package_resource_dir("contracts").joinpath("cve-scan-export", "v7", "schema.json")
    canonical = (
        Path(__file__).resolve().parents[2] / "contracts" / "cve-scan-export" / "v7" / "schema.json"
    )
    assert root.read_bytes() == canonical.read_bytes()
