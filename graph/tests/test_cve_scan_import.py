from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from rootstock_graph.ingestion import cve_scan_contract, import_cve_scan


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_DIR = ROOT / "contracts" / "cve-scan-export" / "v7"


def _fixture(name: str = "valid-minimal.json") -> dict[str, object]:
    return json.loads((CONTRACT_DIR / "fixtures" / name).read_text(encoding="utf-8"))


def test_schema_first_validation_accepts_canonical_fixture() -> None:
    export = cve_scan_contract.validate_export(_fixture())
    assert export.schema_version == 7
    assert export.node_types == frozenset({"Host"})


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda raw: raw.update(generated_at="not-a-date"), "schema validation failed"),
        (lambda raw: raw.update(node_count=2), "node_count"),
        (lambda raw: raw.update(edge_count=1), "edge_count"),
        (lambda raw: raw.update(node_types=["Host", "Finding"]), "node_types"),
        (lambda raw: raw.update(edge_types=["HAS_FINDING"]), "edge_types"),
        (
            lambda raw: raw["nodes"].append(
                {"id": "Host:fixture", "type": "Host", "name": "duplicate"}
            ),
            "duplicate node id",
        ),
    ],
)
def test_cve_export_rejects_invalid_semantic_metadata(mutate, message: str) -> None:
    raw = _fixture()
    mutate(raw)
    with pytest.raises(cve_scan_contract.CveScanImportError, match=message):
        cve_scan_contract.validate_export(raw)


def test_cve_export_rejects_dangling_edge_endpoints() -> None:
    raw = _fixture()
    raw["nodes"].append({"id": "Finding:fixture", "type": "Finding", "name": "finding"})
    raw.update(
        node_count=2,
        node_types=["Host", "Finding"],
        edge_count=1,
        edge_types=["HAS_FINDING"],
    )
    raw["edges"].append({"from": "Host:fixture", "to": "Finding:missing", "type": "HAS_FINDING"})
    with pytest.raises(cve_scan_contract.CveScanImportError, match="not a known node id"):
        cve_scan_contract.validate_export(raw)


def test_validate_only_does_not_open_neo4j(monkeypatch, capsys) -> None:
    fixture = CONTRACT_DIR / "fixtures" / "valid-minimal.json"
    monkeypatch.setattr(
        import_cve_scan,
        "connect_from_args",
        lambda _args: pytest.fail("--validate-only must not open Neo4j"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["rootstock-graph-import-cve-scan", "--input", str(fixture), "--validate-only"],
    )
    assert import_cve_scan.main() == 0
    assert "Validated cve-scan export (1 nodes, 0 relationships)" in capsys.readouterr().out


def test_invalid_contract_exits_before_opening_neo4j(monkeypatch, tmp_path, capsys) -> None:
    invalid_export = tmp_path / "invalid.json"
    invalid_export.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        import_cve_scan,
        "connect_from_args",
        lambda _args: pytest.fail("invalid contracts must not open Neo4j"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["rootstock-graph-import-cve-scan", "--input", str(invalid_export)],
    )

    assert import_cve_scan.main() == 1
    assert "ERROR: schema validation failed:" in capsys.readouterr().err
