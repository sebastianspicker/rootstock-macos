#!/usr/bin/env python3
"""
viewer.py - Generate an interactive HTML graph viewer from Rootstock OpenGraph JSON.

Reads the JSON output of opengraph_export.py and produces a self-contained HTML
file with a Canvas-based graph visualization. Pre-computes force-directed layout
positions in Python so the browser has zero physics delay.

Usage:
    python3 graph/viewer.py --input rootstock-opengraph.json --output viewer.html
    python3 graph/viewer.py --input rootstock-opengraph.json  # writes to rootstock-viewer.html

Pipe from opengraph_export.py:
    python3 graph/opengraph_export.py --output graph.json && python3 graph/viewer.py --input graph.json

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import html as html_mod
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Literal

from constants import INTERACTIVE_GRAPH_MAX_EDGES, INTERACTIVE_GRAPH_MAX_NODES
from viewer_layout import compute_layout

MAX_STATIC_VIEWER_BYTES = 64 * 1024 * 1024


def viewer_script_source(asset_dir: Path) -> str:
    """Return the deterministic, self-contained TypeScript viewer bundle."""
    return (asset_dir / "viewer.bundle.js").read_text()


def render_viewer_html(
    data: dict,
    *,
    title: str,
    mode: Literal["static", "live"],
    api_base_url: str = "",
) -> str:
    """Render either static or authenticated-live viewer bootstrap from one template."""
    asset_dir = Path(__file__).parent
    template = (asset_dir / "viewer_template.html").read_text()
    safe_json = json.dumps(data, ensure_ascii=True).replace("</", "<\\/")
    safe_options = json.dumps(
        {"mode": mode, "apiBaseUrl": api_base_url}, ensure_ascii=True
    ).replace("</", "<\\/")
    bootstrap = (
        "RootstockViewer.mount(" + safe_json + ", " + safe_options + ");"
    )
    replacements = {
        "VIEWER_TITLE": html_mod.escape(title),
        "VIEWER_CSS": (asset_dir / "viewer.css").read_text(),
        "VIEWER_JS": viewer_script_source(asset_dir),
        "VIEWER_BOOTSTRAP": bootstrap,
    }
    return re.sub(
        r"\{\{(VIEWER_TITLE|VIEWER_CSS|VIEWER_JS|VIEWER_BOOTSTRAP)\}\}",
        lambda match: replacements[match.group(1)],
        template,
    )


# ── CLI ─────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an interactive HTML viewer from Rootstock OpenGraph JSON"
    )
    parser.add_argument("--input", "-i", required=True,
                        help="OpenGraph JSON file (output of opengraph_export.py)")
    parser.add_argument("--output", "-o", default=None,
                        help="Output HTML file (default: <input-stem>-viewer.html)")
    return parser.parse_args()


def _load_opengraph_json(input_path: Path) -> object | None:
    """Read an untrusted regular JSON file only when it fits the static size budget."""
    if not input_path.exists():
        print(f"ERROR: File not found: {input_path}", file=sys.stderr)
        return None
    try:
        file_status = input_path.stat()
        if not stat.S_ISREG(file_status.st_mode):
            print(
                f"ERROR: Input must be a regular file: {input_path}",
                file=sys.stderr,
            )
            return None
        if file_status.st_size > MAX_STATIC_VIEWER_BYTES:
            print(
                "ERROR: Input exceeds the static viewer limit of "
                f"{MAX_STATIC_VIEWER_BYTES} bytes",
                file=sys.stderr,
            )
            return None
        return json.loads(input_path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as e:
        print(f"ERROR: Invalid JSON in {input_path}: {e}", file=sys.stderr)
        return None


def _graph_members(data: object) -> tuple[dict, list, list] | None:
    if not isinstance(data, dict) or not isinstance(data.get("graph"), dict):
        print("ERROR: Input does not contain an OpenGraph graph object", file=sys.stderr)
        return None
    graph = data["graph"]
    nodes, edges = graph.get("nodes"), graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        print(
            "ERROR: Input does not look like OpenGraph JSON "
            "(graph.nodes and graph.edges must be arrays)",
            file=sys.stderr,
        )
        return None
    return graph, nodes, edges


def _graph_fits_static_viewer(nodes: list, edges: list) -> bool:
    return (
        len(nodes) <= INTERACTIVE_GRAPH_MAX_NODES
        and len(edges) <= INTERACTIVE_GRAPH_MAX_EDGES
    )


def _validated_graph(data: object) -> dict | None:
    """Validate the bounded OpenGraph container before layout or HTML generation."""
    members = _graph_members(data)
    if members is None:
        return None
    graph, nodes, edges = members
    if not _graph_fits_static_viewer(nodes, edges):
        print(
            "ERROR: Graph exceeds the static viewer limit of "
            f"{INTERACTIVE_GRAPH_MAX_NODES} nodes and "
            f"{INTERACTIVE_GRAPH_MAX_EDGES} edges",
            file=sys.stderr,
        )
        return None
    if not all(isinstance(member, dict) for member in [*nodes, *edges]):
        print("ERROR: Graph nodes and edges must be objects", file=sys.stderr)
        return None
    return graph


def _compute_viewer_layout(graph: dict) -> tuple[int, int]:
    node_list = graph["nodes"]
    edge_list = graph["edges"]
    n_nodes = len(node_list)
    n_edges = len(edge_list)

    print(f"Computing layout for {n_nodes} nodes, {n_edges} edges...", end=" ", flush=True)
    iters = min(300, max(100, 500 - n_nodes // 10))
    compute_layout(node_list, edge_list, iterations=iters)
    print("done.")
    return n_nodes, n_edges


def _viewer_output_path(input_path: Path, output: str | None) -> Path:
    if output:
        return Path(output)
    return input_path.with_name(input_path.stem + "-viewer.html")


def _viewer_html(data: dict) -> str:
    hostname = data.get("metadata", {}).get("hostname", "Graph")
    title = f"{hostname} Attack Graph"
    return render_viewer_html(data, title=title, mode="static")


def _write_private_viewer(path: Path, content: str) -> None:
    """Write confidential graph HTML to a regular file with owner-only access."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    for optional_flag in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, optional_flag, 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"Refusing to write viewer to non-regular file: {path}")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            output.write(content)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main() -> int:
    args = _parse_args()
    input_path = Path(args.input)
    data = _load_opengraph_json(input_path)
    if not isinstance(data, dict):
        return 1
    graph = _validated_graph(data)
    if graph is None:
        return 1
    n_nodes, n_edges = _compute_viewer_layout(graph)
    output_path = _viewer_output_path(input_path, args.output)
    html_out = _viewer_html(data)
    _write_private_viewer(output_path, html_out)
    print(f"Generated {output_path} ({n_nodes} nodes, {n_edges} edges)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
