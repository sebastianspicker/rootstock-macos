from __future__ import annotations

import stat
from pathlib import Path

import pytest

from constants import INTERACTIVE_GRAPH_MAX_EDGES, INTERACTIVE_GRAPH_MAX_NODES
from viewer import (
    _load_opengraph_json,
    _validated_graph,
    _write_private_viewer,
)


def test_private_viewer_write_enforces_owner_only_permissions(tmp_path: Path) -> None:
    output = tmp_path / "viewer.html"
    output.write_text("old", encoding="utf-8")
    output.chmod(0o644)

    _write_private_viewer(output, "new")

    assert output.read_text(encoding="utf-8") == "new"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_private_viewer_write_refuses_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.html"
    target.write_text("unchanged", encoding="utf-8")
    output = tmp_path / "viewer.html"
    output.symlink_to(target)

    with pytest.raises(OSError):
        _write_private_viewer(output, "replacement")

    assert target.read_text(encoding="utf-8") == "unchanged"


def test_static_viewer_rejects_oversized_graph(capsys) -> None:
    data = {
        "graph": {
            "nodes": [{}] * (INTERACTIVE_GRAPH_MAX_NODES + 1),
            "edges": [],
        }
    }

    assert _validated_graph(data) is None
    assert "static viewer limit" in capsys.readouterr().err

    data = {
        "graph": {
            "nodes": [],
            "edges": [{}] * (INTERACTIVE_GRAPH_MAX_EDGES + 1),
        }
    }
    assert _validated_graph(data) is None


def test_static_viewer_rejects_non_object_members(capsys) -> None:
    assert _validated_graph({"graph": {"nodes": ["bad"], "edges": []}}) is None
    assert "must be objects" in capsys.readouterr().err


def test_static_viewer_rejects_oversized_input_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    input_path = tmp_path / "graph.json"
    input_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr("viewer.MAX_STATIC_VIEWER_BYTES", 1)

    assert _load_opengraph_json(input_path) is None
    assert "static viewer limit" in capsys.readouterr().err


def test_static_viewer_reports_excessive_json_nesting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    input_path = tmp_path / "graph.json"
    input_path.write_text("{}", encoding="utf-8")

    def reject_deep_json(_content: str) -> object:
        raise RecursionError("fixture nesting limit")

    monkeypatch.setattr("viewer.json.loads", reject_deep_json)

    assert _load_opengraph_json(input_path) is None
    assert "fixture nesting limit" in capsys.readouterr().err
