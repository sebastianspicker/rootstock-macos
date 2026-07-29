from __future__ import annotations

import re
from pathlib import Path

from opengraph_export import EDGE_TYPE_MAP, NODE_TYPE_MAP

FIXTURE_SOURCE = (
    Path(__file__).resolve().parents[2] / "scripts" / "release-screenshot-fixture.mjs"
)
CAPTURE_SOURCE = (
    Path(__file__).resolve().parents[2] / "scripts" / "capture-release-screenshots.mjs"
)
MOCKUP_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "mockups"
    / "rootstock-paths-workspace.html"
)
NODE_CALL_RE = re.compile(
    r'node\(\s*"(?P<id>[^"]+)"\s*,\s*"(?P<kind>rs_[^"]+)"',
    re.MULTILINE,
)
EDGE_CALL_RE = re.compile(
    r'edge\(\s*"[^"]+"\s*,\s*"[^"]+"\s*,\s*"(?P<kind>rs_[^"]+)"'
    r"\s*,\s*(?P<traversable>true|false)\s*\)",
    re.MULTILINE,
)


def test_release_screenshot_fixture_uses_authoritative_graph_vocabulary() -> None:
    source = FIXTURE_SOURCE.read_text(encoding="utf-8")
    node_calls = NODE_CALL_RE.findall(source)
    edge_calls = EDGE_CALL_RE.findall(source)
    node_kinds = {mapping["kind"] for mapping in NODE_TYPE_MAP.values()}
    edge_by_kind = {mapping["kind"]: mapping for mapping in EDGE_TYPE_MAP.values()}

    assert len(node_calls) == 7
    assert len({node_id for node_id, _kind in node_calls}) == 7
    assert {kind for _node_id, kind in node_calls} <= node_kinds
    assert len(edge_calls) == 7
    assert {kind for kind, _traversable in edge_calls} <= edge_by_kind.keys()
    for kind, traversable in edge_calls:
        assert edge_by_kind[kind]["traversable"] is (traversable == "true")


def test_release_screenshot_fixture_contains_no_local_identity_markers() -> None:
    for source_path in (FIXTURE_SOURCE, MOCKUP_SOURCE):
        source = source_path.read_text(encoding="utf-8").lower()
        for marker in ("/users/", "sebastian", "acme", "macbook", "scan_id"):
            assert marker not in source


def test_release_screenshots_render_the_maintained_viewer() -> None:
    source = CAPTURE_SOURCE.read_text(encoding="utf-8")

    assert '"graph", "viewer_template.html"' in source
    assert '"graph", "viewer.css"' in source
    assert '"graph", "viewer.bundle.js"' in source
    assert "rootstock-paths-workspace.html" not in source


def test_release_screenshot_mockup_matches_the_synthetic_fixture() -> None:
    mockup = MOCKUP_SOURCE.read_text(encoding="utf-8")
    fixture = FIXTURE_SOURCE.read_text(encoding="utf-8")

    for value in (
        "synthetic-alpha-fixture",
        "public-release-screenshot-fixture",
        "Unsigned Helper",
        "Privileged Editor",
        "Shared Credential",
        "Protected Configuration",
        "Login Persistence",
        "Full Disk Access",
        "Enable Library Validation",
    ):
        assert value in fixture
        assert value in mockup
