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


# ── CLI ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate an interactive HTML viewer from Rootstock OpenGraph JSON"
    )
    parser.add_argument("--input", "-i", required=True,
                        help="OpenGraph JSON file (output of opengraph_export.py)")
    parser.add_argument("--output", "-o", default=None,
                        help="Output HTML file (default: <input-stem>-viewer.html)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: File not found: {input_path}", file=sys.stderr)
        return 1

    try:
        data = json.loads(input_path.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {input_path}: {e}", file=sys.stderr)
        return 1

    graph = data.get("graph", {})
    if "nodes" not in graph or "edges" not in graph:
        print("ERROR: Input does not look like OpenGraph JSON (missing graph.nodes or graph.edges)", file=sys.stderr)
        return 1

    # Pre-compute layout positions
    node_list = graph["nodes"]
    edge_list = graph["edges"]
    n_nodes = len(node_list)
    n_edges = len(edge_list)

    print(f"Computing layout for {n_nodes} nodes, {n_edges} edges...", end=" ", flush=True)
    iters = min(300, max(100, 500 - n_nodes // 10))
    compute_layout(node_list, edge_list, iterations=iters)
    print("done.")

    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.with_name(input_path.stem + "-viewer.html")

    # Build title
    hostname = data.get("metadata", {}).get("hostname", "Graph")
    title = f"{hostname} Attack Graph"

    # Generate HTML
    safe_title = html_mod.escape(title)
    safe_json = json.dumps(data).replace("</", "<\\/")
    template = (Path(__file__).parent / "viewer_template.html").read_text()
    html_out = template.replace("{{VIEWER_TITLE}}", safe_title).replace(
        "{{VIEWER_DATA}}", safe_json
    )

    output_path.write_text(html_out)
    print(f"Generated {output_path} ({n_nodes} nodes, {n_edges} edges)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
