"""Synthetic layout invariants and deterministic convergence checks."""

from unittest.mock import patch
import math

import pytest

from rootstock_graph.reporting import viewer_layout as layout
from rootstock_graph.reporting.viewer_quadtree import apply_tree_repulsion


@pytest.mark.parametrize("count", [0, 1, 256, 257, 1000])
def test_layout_is_repeatable_finite_and_bounded(count):
    nodes = [{"id": str(i), "kind": str(i % 5)} for i in range(count)]
    second = [dict(node) for node in nodes]
    edges = [{"source": "0", "target": "1", "properties": {"evidence": "synthetic"}}]
    layout.compute_layout(nodes, edges, iterations=21)
    layout.compute_layout(second, edges, iterations=21)
    assert nodes == second
    assert all(
        math.isfinite(node[axis]) and 50 <= node[axis] <= 1950
        for node in nodes
        for axis in ("x", "y")
    )
    assert edges == [{"source": "0", "target": "1", "properties": {"evidence": "synthetic"}}]


@pytest.mark.parametrize("distance", [499.9, 500, 500.1])
def test_tree_cutoff_and_coincident_points(distance):
    nodes = [{"x": 0.0, "y": 0.0}] * 260 + [{"x": distance, "y": 0.0}]
    fx, fy = [0.0] * len(nodes), [0.0] * len(nodes)
    apply_tree_repulsion(nodes, fx, fy, 800, 5)
    expected = -800 / distance if distance <= 500 else 0
    assert fx[0] == pytest.approx(expected)
    assert fx[-1] == pytest.approx(-expected * 260)
    assert fy == [0.0] * len(nodes)


def test_tree_opens_cells_crossing_cutoff():
    nodes = [{"x": 0.0, "y": 0.0}]
    nodes += [{"x": 499.0, "y": 0.0}] * 100 + [{"x": 501.0, "y": 0.0}] * 100
    fx, fy = [0.0] * len(nodes), [0.0] * len(nodes)
    apply_tree_repulsion(nodes, fx, fy, 800, 5)
    assert fx[0] == pytest.approx(-100 * 800 / 499)


def test_exact_path_threshold():
    with (
        patch.object(layout, "_apply_full_repulsion") as exact,
        patch.object(layout, "apply_tree_repulsion") as tree,
    ):
        for count in (256, 257):
            layout._apply_repulsion([{}] * count, [], [], 800, 5)
    assert exact.call_count == tree.call_count == 1


@pytest.mark.parametrize("budget,expected", [(3, 3), (19, 19), (21, 20), (300, 20)])
def test_convergence_keeps_budget_and_minimum(budget, expected):
    with patch.object(layout, "_apply_velocity", return_value=0.01) as velocity:
        layout._simulate_layout([{"x": 1000.0, "y": 1000.0}], [], 2000, 2000, budget)
    assert velocity.call_count == expected


def test_convergence_requires_ten_consecutive_small_steps():
    displacements = [1.0] * 15 + [0.01] * 9 + [1.0] + [0.01] * 10
    with patch.object(layout, "_apply_velocity", side_effect=displacements) as velocity:
        layout._simulate_layout([{"x": 1000.0, "y": 1000.0}], [], 2000, 2000, 100)
    assert velocity.call_count == 35


def test_large_repulsion_bounds_exact_leaf_work():
    from rootstock_graph.reporting import viewer_quadtree as tree

    count = 1024
    nodes = [{"x": (i % 32) * 10.0, "y": (i // 32) * 10.0} for i in range(count)]
    with patch.object(tree, "_leaf_force", wraps=tree._leaf_force) as leaves:
        tree.apply_tree_repulsion(nodes, [0.0] * count, [0.0] * count, 800, 5)
    leaf_members = sum(call.args[1].mass for call in leaves.call_args_list)
    assert leaf_members < count * count // 3
