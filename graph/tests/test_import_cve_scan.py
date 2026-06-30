from __future__ import annotations

from unittest import TestCase

import json
from pathlib import Path

import pytest

from import_cve_scan import (
    CveScanImportError,
    build_affected_by_alias_records,
    build_node_records,
    import_cve_scan_export,
    validate_export,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "examples" / "cve-scan-export.json"


checks = TestCase()


class _Result:
    def __init__(self, count: int) -> None:
        self.count = count

    def single(self) -> dict[str, int]:
        return {"n": self.count}


class _RecordingSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def run(self, query: str, **kwargs: object) -> _Result:
        self.calls.append((query, kwargs))
        records = kwargs.get("records")
        return _Result(len(records) if isinstance(records, list) else 0)


def _fixture_data() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_fixture_export_validates() -> None:
    export = validate_export(_fixture_data())

    checks.assertEqual(export.schema_version, 7)
    checks.assertEqual(export.scope_name, "rootstock-cve-scan-demo")
    checks.assertEqual(len(export.nodes), 11)
    checks.assertEqual(len(export.edges), 13)


def test_validation_rejects_unsupported_node_label() -> None:
    data = _fixture_data()
    node = dict(data["nodes"][0])  # type: ignore[index]
    node["type"] = "UnsafeLabel"
    data["nodes"] = [node, *data["nodes"][1:]]  # type: ignore[index]
    data["node_types"] = [*data["node_types"], "UnsafeLabel"]  # type: ignore[index]

    with pytest.raises(CveScanImportError, match="unsupported values"):
        validate_export(data)


def test_validation_rejects_unsupported_edge_type() -> None:
    data = _fixture_data()
    edge = dict(data["edges"][0])  # type: ignore[index]
    edge["type"] = "DROPS_DATABASE"
    data["edges"] = [edge, *data["edges"][1:]]  # type: ignore[index]
    data["edge_types"] = [*data["edge_types"], "DROPS_DATABASE"]  # type: ignore[index]
    data["edge_vocabulary"] = [*data["edge_vocabulary"], "DROPS_DATABASE"]  # type: ignore[index]

    with pytest.raises(CveScanImportError, match="unsupported values"):
        validate_export(data)


def test_validation_rejects_missing_edge_endpoint() -> None:
    data = _fixture_data()
    edge = dict(data["edges"][0])  # type: ignore[index]
    edge["to"] = "Package:missing"
    data["edges"] = [edge, *data["edges"][1:]]  # type: ignore[index]

    with pytest.raises(CveScanImportError, match="edge target"):
        validate_export(data)


def test_node_records_preserve_package_source_and_add_provenance() -> None:
    export = validate_export(_fixture_data())
    records = build_node_records(export)
    package = records["Package"][0]["props"]
    vulnerability = records["Vulnerability"][0]

    checks.assertTrue(isinstance(package, dict))
    checks.assertEqual(package["source"], "cve-scan")
    checks.assertEqual(package["cve_scan_original_source"], "repo/requirements.txt")
    checks.assertEqual(package["cve_scan_scope_name"], "rootstock-cve-scan-demo")
    checks.assertEqual(vulnerability["cve_id"], "CVE-2026-9701")


def test_affected_by_alias_records_follow_vulnerability_affects_asset_edges() -> None:
    export = validate_export(_fixture_data())
    aliases = build_affected_by_alias_records(export)

    checks.assertEqual(
        aliases,
        [
            {
                "source_id": "Package:pypi_fastapi_0.115.0_repo_requirements.txt",
                "target_id": "Vulnerability:CVE-2026-9701",
            },
            {
                "source_id": "Service:app.example.test_443_https",
                "target_id": "Vulnerability:CVE-2026-9701",
            },
        ],
    )


def test_import_uses_batched_merges_and_alias_edges() -> None:
    export = validate_export(_fixture_data())
    session = _RecordingSession()

    counts = import_cve_scan_export(session, export)

    checks.assertEqual(counts, {"nodes": 11, "edges": 13, "affected_by_aliases": 2})
    checks.assertTrue(
        any("MERGE (n:Package {id: row.id})" in query for query, _ in session.calls)
    )
    checks.assertTrue(
        any(
            "MERGE (n:Vulnerability {cve_id: row.cve_id})" in query
            for query, _ in session.calls
        )
    )
    checks.assertTrue(
        any(
            "MERGE (asset)-[r:AFFECTED_BY]->(vulnerability)" in query
            for query, _ in session.calls
        )
    )
