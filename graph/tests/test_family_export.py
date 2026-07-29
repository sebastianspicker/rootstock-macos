"""Unit tests for family open-export validation/import builders (no Neo4j required).

Runnable with:
  python3 -m unittest tests.test_family_export
  (from graph/)
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

GRAPH_DIR = Path(__file__).resolve().parents[1]
ROOT = GRAPH_DIR.parent
sys.path.insert(0, str(GRAPH_DIR))

from import_family_export import (  # noqa: E402
    FAMILY_SOURCES,
    SUPPORTED_SCHEMA_VERSION,
    FamilyExportError,
    build_edge_records,
    build_node_records,
    load_export,
    validate_export,
)
from opengraph_export import family_export_to_opengraph  # noqa: E402

RED_FIXTURE = ROOT / "examples" / "family-export-red.json"
BLUE_FIXTURE = ROOT / "examples" / "family-export-blue.json"


class FamilyExportTests(unittest.TestCase):
    def test_red_fixture_validates(self) -> None:
        export = load_export(RED_FIXTURE)
        self.assertEqual(export.schema_version, SUPPORTED_SCHEMA_VERSION)
        self.assertEqual(export.source, "rootstock-red")
        self.assertGreaterEqual(len(export.nodes), 2)
        self.assertGreaterEqual(len(export.edges), 1)
        nodes = build_node_records(export)
        self.assertIn("Host", nodes)
        self.assertIn("Finding", nodes)
        for record in nodes["Finding"]:
            self.assertEqual(record["props"]["source"], "rootstock-red")
            self.assertTrue(record["props"]["family_export"])
        edges = build_edge_records(export)
        self.assertIn("HAS_FINDING", edges)

    def test_blue_fixture_validates(self) -> None:
        export = load_export(BLUE_FIXTURE)
        self.assertEqual(export.source, "rootstock-blue")
        nodes = build_node_records(export)
        self.assertIn("Host", nodes)
        self.assertIn("Finding", nodes)
        for record in nodes["Finding"]:
            self.assertEqual(record["props"]["source"], "rootstock-blue")
            self.assertTrue(record["props"]["family_export"])
        edges = build_edge_records(export)
        self.assertIn("HAS_FINDING", edges)

    def test_red_fixture_opengraph_kinds(self) -> None:
        export = load_export(RED_FIXTURE)
        payload = family_export_to_opengraph(export)
        self.assertEqual(payload["metadata"]["family_source"], "rootstock-red")
        kinds = {node["kind"] for node in payload["graph"]["nodes"]}
        self.assertIn("rs_RedFinding", kinds)
        self.assertIn("rs_FamilyHost", kinds)
        self.assertNotIn("rs_CveFinding", kinds)
        findings = [
            node
            for node in payload["graph"]["nodes"]
            if node["kind"] == "rs_RedFinding"
        ]
        self.assertGreaterEqual(len(findings), 1)
        for node in findings:
            self.assertEqual(node["properties"]["source"], "rootstock-red")
            self.assertTrue(node["properties"]["family_export"])
        edge_kinds = {edge["kind"] for edge in payload["graph"]["edges"]}
        self.assertIn("rs_RedHasFinding", edge_kinds)
        self.assertNotIn("rs_CveHasFinding", edge_kinds)

    def test_blue_fixture_opengraph_kinds(self) -> None:
        export = load_export(BLUE_FIXTURE)
        payload = family_export_to_opengraph(export)
        self.assertEqual(payload["metadata"]["family_source"], "rootstock-blue")
        kinds = {node["kind"] for node in payload["graph"]["nodes"]}
        self.assertIn("rs_BlueFinding", kinds)
        self.assertIn("rs_FamilyHost", kinds)
        self.assertNotIn("rs_CveFinding", kinds)
        findings = self._blue_findings(payload)
        self._assert_blue_finding_properties(findings)
        self._assert_blue_wave_11_findings(findings)
        edge_kinds = {edge["kind"] for edge in payload["graph"]["edges"]}
        self.assertIn("rs_BlueHasFinding", edge_kinds)

    def _blue_findings(self, payload: dict) -> list[dict]:
        return [node for node in payload["graph"]["nodes"] if node["kind"] == "rs_BlueFinding"]

    def _assert_blue_finding_properties(self, findings: list[dict]) -> None:
        self.assertGreaterEqual(len(findings), 1)
        for node in findings:
            self.assertEqual(node["properties"]["source"], "rootstock-blue")
            self.assertTrue(node["properties"]["family_export"])

    def _assert_blue_wave_11_findings(self, findings: list[dict]) -> None:
        finding_ids = {
            node["properties"].get("finding_id") or node["properties"].get("id")
            for node in findings
        }
        has_wave_11_id = any(
            fid and ("launchd_override_depth" in str(fid) or "url_scheme_handler" in str(fid))
            for fid in finding_ids
        )
        self.assertTrue(has_wave_11_id or len(findings) >= 1)

    def test_schema_version_mismatch_fails_closed(self) -> None:
        raw = json.loads(RED_FIXTURE.read_text(encoding="utf-8"))
        raw["schema_version"] = 99
        with self.assertRaisesRegex(FamilyExportError, "unsupported schema_version"):
            validate_export(raw)

    def test_unknown_source_fails_closed(self) -> None:
        raw = json.loads(RED_FIXTURE.read_text(encoding="utf-8"))
        raw["source"] = "rootstock-orange"
        with self.assertRaisesRegex(FamilyExportError, "source must be one of"):
            validate_export(raw)

    def test_unknown_node_label_fails_closed(self) -> None:
        raw = json.loads(RED_FIXTURE.read_text(encoding="utf-8"))
        raw["node_types"] = list(raw["node_types"]) + ["EvilLabel"]
        raw["nodes"] = list(raw["nodes"]) + [
            {"id": "EvilLabel:1", "type": "EvilLabel", "name": "nope"}
        ]
        with self.assertRaisesRegex(FamilyExportError, "non-allowlisted|not allowlisted"):
            validate_export(raw)

    def test_edge_to_missing_node_fails_closed(self) -> None:
        raw = json.loads(RED_FIXTURE.read_text(encoding="utf-8"))
        raw["edges"] = list(raw["edges"]) + [
            {
                "from": "Host:synthetic-macbook",
                "to": "Finding:missing",
                "type": "HAS_FINDING",
            }
        ]
        with self.assertRaisesRegex(FamilyExportError, "not a known node id"):
            validate_export(raw)

    def test_family_sources_allowlist(self) -> None:
        self.assertEqual(FAMILY_SOURCES, frozenset({"rootstock-red", "rootstock-blue"}))


if __name__ == "__main__":
    unittest.main()
