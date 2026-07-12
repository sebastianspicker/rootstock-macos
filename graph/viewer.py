#!/usr/bin/env python3
"""
viewer.py — Generate an interactive HTML graph viewer from Rootstock OpenGraph JSON.

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
import sys
from pathlib import Path

from viewer_layout import compute_layout

VIEWER_SCRIPT_FILES = (
    "viewer.js",
    "viewer_spatial.js",
    "viewer_render.js",
    "viewer_analysis.js",
    "viewer_controls.js",
    "viewer_live.js",
    "viewer_shell.js",
)


def viewer_script_source(asset_dir: Path) -> str:
    """Return viewer modules in browser execution order."""
    return "\n".join((asset_dir / name).read_text() for name in VIEWER_SCRIPT_FILES)


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


def _load_opengraph_json(input_path: Path) -> dict | None:
    if not input_path.exists():
        print(f"ERROR: File not found: {input_path}", file=sys.stderr)
        return None
    try:
        return json.loads(input_path.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {input_path}: {e}", file=sys.stderr)
        return None


def _validated_graph(data: dict) -> dict | None:
    graph = data.get("graph", {})
    if "nodes" not in graph or "edges" not in graph:
        print("ERROR: Input does not look like OpenGraph JSON (missing graph.nodes or graph.edges)", file=sys.stderr)
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
    safe_title = html_mod.escape(title)
    safe_json = json.dumps(data).replace("</", "<\\/")
    asset_dir = Path(__file__).parent
    template = (asset_dir / "viewer_template.html").read_text()
    return (
        template.replace("{{VIEWER_TITLE}}", safe_title)
        .replace("{{VIEWER_CSS}}", (asset_dir / "viewer.css").read_text())
        .replace("{{VIEWER_JS}}", viewer_script_source(asset_dir))
        .replace("null /* VIEWER_DATA */", safe_json)
    )


def main() -> int:
    args = _parse_args()
    input_path = Path(args.input)
    data = _load_opengraph_json(input_path)
    if data is None:
        return 1
    graph = _validated_graph(data)
    if graph is None:
        return 1
    n_nodes, n_edges = _compute_viewer_layout(graph)
    output_path = _viewer_output_path(input_path, args.output)
    html_out = _viewer_html(data)
    output_path.write_text(html_out)
    print(f"Generated {output_path} ({n_nodes} nodes, {n_edges} edges)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
