import os
import sys
from unittest import TestCase

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from viewer_layout import compute_layout


def _fixture_nodes() -> list[dict]:
    return [
        {"id": "app-1", "kind": "Application"},
        {"id": "grant-1", "kind": "TCCGrant"},
        {"id": "svc-1", "kind": "Service"},
    ]


checks = TestCase()


def test_compute_layout_is_deterministic_and_clamps_to_viewport():
    edges = [
        {"source": "app-1", "target": "grant-1"},
        {"source": "missing", "target": "svc-1"},
    ]
    first = _fixture_nodes()
    second = _fixture_nodes()

    compute_layout(first, edges, width=400, height=300, iterations=5)
    compute_layout(second, edges, width=400, height=300, iterations=5)

    checks.assertEqual(
        [(node["x"], node["y"]) for node in first],
        [(node["x"], node["y"]) for node in second],
    )
    checks.assertTrue(all(50 <= node["x"] <= 350 for node in first))
    checks.assertTrue(all(50 <= node["y"] <= 250 for node in first))


def test_compute_layout_leaves_empty_graph_unchanged():
    nodes: list[dict] = []

    compute_layout(nodes, [], iterations=1)

    checks.assertEqual(nodes, [])
