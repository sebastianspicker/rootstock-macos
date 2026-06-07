"""
viewer_layout.py — Force-directed layout computation for Rootstock graph viewer.

Extracted from viewer.py to keep layout logic separate from HTML generation.
"""

from __future__ import annotations

import math


class _LayoutJitter:
    def __init__(self, seed: int = 42) -> None:
        self._seed = seed
        self._index = 0

    def fraction(self) -> float:
        self._index += 1
        value = math.sin((self._seed + self._index) * 12.9898) * 43758.5453
        return value - math.floor(value)


def _initialize_positions(
    nodes: list[dict],
    width: float,
    height: float,
    jitter: _LayoutJitter,
) -> None:
    for node in nodes:
        node["x"] = width / 2 + (jitter.fraction() - 0.5) * width * 0.8
        node["y"] = height / 2 + (jitter.fraction() - 0.5) * height * 0.8


def _edge_pairs(nodes: list[dict], edges: list[dict]) -> list[tuple[int, int]]:
    id_to_idx = {node["id"]: i for i, node in enumerate(nodes)}
    pairs = []
    for edge in edges:
        si = id_to_idx.get(edge.get("source"))
        ti = id_to_idx.get(edge.get("target"))
        if si is not None and ti is not None:
            pairs.append((si, ti))
    return pairs


def _kind_groups(nodes: list[dict]) -> dict[str, list[int]]:
    kind_groups: dict[str, list[int]] = {}
    for i, node in enumerate(nodes):
        kind = node.get("kind", "")
        kind_groups.setdefault(kind, []).append(i)
    return kind_groups


def _position_kind_clusters(
    nodes: list[dict],
    width: float,
    height: float,
    jitter: _LayoutJitter,
) -> None:
    kind_groups = _kind_groups(nodes)
    kinds = list(kind_groups.keys())
    for ki, kind in enumerate(kinds):
        angle = 2 * math.pi * ki / max(len(kinds), 1)
        cx = width / 2 + math.cos(angle) * width * 0.3
        cy = height / 2 + math.sin(angle) * height * 0.3
        indices = kind_groups[kind]
        for j, idx in enumerate(indices):
            spread_angle = 2 * math.pi * j / max(len(indices), 1)
            r = min(100, len(indices) * 2)
            nodes[idx]["x"] = (
                cx + math.cos(spread_angle) * r + (jitter.fraction() - 0.5) * 20
            )
            nodes[idx]["y"] = (
                cy + math.sin(spread_angle) * r + (jitter.fraction() - 0.5) * 20
            )


def _apply_repulsion_pair(
    nodes: list[dict],
    fx: list[float],
    fy: list[float],
    i: int,
    j: int,
    effective_repulsion: float,
    min_dist: float,
) -> None:
    dx = nodes[i]["x"] - nodes[j]["x"]
    dy = nodes[i]["y"] - nodes[j]["y"]
    dist_sq = max(dx * dx + dy * dy, min_dist * min_dist)
    force = effective_repulsion / dist_sq
    fdx = dx * force
    fdy = dy * force
    fx[i] += fdx
    fy[i] += fdy
    fx[j] -= fdx
    fy[j] -= fdy


def _apply_full_repulsion(
    nodes: list[dict],
    fx: list[float],
    fy: list[float],
    effective_repulsion: float,
    min_dist: float,
) -> None:
    for i in range(len(nodes)):
        xi, yi = nodes[i]["x"], nodes[i]["y"]
        for j in range(i + 1, len(nodes)):
            dx = xi - nodes[j]["x"]
            dy = yi - nodes[j]["y"]
            if dx * dx + dy * dy > 500 * 500:
                continue
            _apply_repulsion_pair(nodes, fx, fy, i, j, effective_repulsion, min_dist)


def _layout_grid(nodes: list[dict], cell_size: float) -> dict[tuple[int, int], list[int]]:
    grid: dict[tuple[int, int], list[int]] = {}
    for i, node in enumerate(nodes):
        gx = int(node["x"] / cell_size)
        gy = int(node["y"] / cell_size)
        grid.setdefault((gx, gy), []).append(i)
    return grid


def _apply_grid_repulsion(
    nodes: list[dict],
    fx: list[float],
    fy: list[float],
    effective_repulsion: float,
    min_dist: float,
) -> None:
    cell_size = 100.0
    grid = _layout_grid(nodes, cell_size)
    for i, node in enumerate(nodes):
        gx = int(node["x"] / cell_size)
        gy = int(node["y"] / cell_size)
        for dx_c in range(-2, 3):
            for dy_c in range(-2, 3):
                cell = grid.get((gx + dx_c, gy + dy_c))
                if not cell:
                    continue
                for j in cell:
                    if j > i:
                        _apply_repulsion_pair(
                            nodes, fx, fy, i, j, effective_repulsion, min_dist
                        )


def _apply_repulsion(
    nodes: list[dict],
    fx: list[float],
    fy: list[float],
    effective_repulsion: float,
    min_dist: float,
) -> None:
    if len(nodes) <= 3000:
        _apply_full_repulsion(nodes, fx, fy, effective_repulsion, min_dist)
    else:
        _apply_grid_repulsion(nodes, fx, fy, effective_repulsion, min_dist)


def _apply_attraction(
    nodes: list[dict],
    edge_pairs: list[tuple[int, int]],
    fx: list[float],
    fy: list[float],
    attraction: float,
    min_dist: float,
) -> None:
    for si, ti in edge_pairs:
        dx = nodes[ti]["x"] - nodes[si]["x"]
        dy = nodes[ti]["y"] - nodes[si]["y"]
        dist = math.sqrt(dx * dx + dy * dy) or min_dist
        force = attraction * dist
        fdx = dx * force
        fdy = dy * force
        fx[si] += fdx
        fy[si] += fdy
        fx[ti] -= fdx
        fy[ti] -= fdy


def _apply_centering(
    nodes: list[dict],
    fx: list[float],
    fy: list[float],
    width: float,
    height: float,
    center_pull: float,
) -> None:
    for i, node in enumerate(nodes):
        fx[i] += (width / 2 - node["x"]) * center_pull
        fy[i] += (height / 2 - node["y"]) * center_pull


def _apply_velocity(
    nodes: list[dict],
    vx: list[float],
    vy: list[float],
    fx: list[float],
    fy: list[float],
    damping: float,
    max_displacement: float,
) -> None:
    for i, node in enumerate(nodes):
        vx[i] = (vx[i] + fx[i]) * damping
        vy[i] = (vy[i] + fy[i]) * damping
        disp = math.sqrt(vx[i] * vx[i] + vy[i] * vy[i])
        if disp > max_displacement:
            scale = max_displacement / disp
            vx[i] *= scale
            vy[i] *= scale
        node["x"] += vx[i]
        node["y"] += vy[i]


def _simulate_layout(
    nodes: list[dict],
    edge_pairs: list[tuple[int, int]],
    width: float,
    height: float,
    iterations: int,
) -> None:
    repulsion = 800.0
    attraction = 0.005
    center_pull = 0.01
    damping = 0.9
    min_dist = 5.0
    vx = [0.0] * len(nodes)
    vy = [0.0] * len(nodes)

    for iteration in range(iterations):
        temp = 1.0 - iteration / iterations
        fx = [0.0] * len(nodes)
        fy = [0.0] * len(nodes)
        _apply_repulsion(nodes, fx, fy, repulsion * (0.3 + 0.7 * temp), min_dist)
        _apply_attraction(nodes, edge_pairs, fx, fy, attraction, min_dist)
        _apply_centering(nodes, fx, fy, width, height, center_pull)
        _apply_velocity(nodes, vx, vy, fx, fy, damping, 50.0 * temp + 1.0)


def _clamp_positions(nodes: list[dict], width: float, height: float) -> None:
    margin = 50.0
    for node in nodes:
        node["x"] = round(max(margin, min(width - margin, node["x"])), 1)
        node["y"] = round(max(margin, min(height - margin, node["y"])), 1)


def compute_layout(
    nodes: list[dict],
    edges: list[dict],
    width: float = 2000.0,
    height: float = 2000.0,
    iterations: int = 300,
) -> None:
    """
    Compute force-directed layout positions in-place. Sets 'x' and 'y' on each node.
    Simple iterative approach: repulsive charge between all nodes (approximated),
    attractive spring along edges, and centering force.
    """
    n = len(nodes)
    if n == 0:
        return

    jitter = _LayoutJitter()
    _initialize_positions(nodes, width, height, jitter)
    _position_kind_clusters(nodes, width, height, jitter)
    _simulate_layout(nodes, _edge_pairs(nodes, edges), width, height, iterations)
    _clamp_positions(nodes, width, height)
