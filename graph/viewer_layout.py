"""
viewer_layout.py — Force-directed layout computation for Rootstock graph viewer.

Extracted from viewer.py to keep layout logic separate from HTML generation.
"""

from __future__ import annotations

import math
import random


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

    # Initialize random positions
    rng = random.Random(42)
    for node in nodes:
        node["x"] = width / 2 + (rng.random() - 0.5) * width * 0.8
        node["y"] = height / 2 + (rng.random() - 0.5) * height * 0.8

    # Build index
    id_to_idx = {node["id"]: i for i, node in enumerate(nodes)}

    # Parse edges into index pairs
    edge_pairs = []
    for e in edges:
        si = id_to_idx.get(e.get("source"))
        ti = id_to_idx.get(e.get("target"))
        if si is not None and ti is not None:
            edge_pairs.append((si, ti))

    # Build adjacency for degree-based sizing
    degree = [0] * n
    for si, ti in edge_pairs:
        degree[si] += 1
        degree[ti] += 1

    # Group nodes by kind for initial clustering
    kind_groups: dict[str, list[int]] = {}
    for i, node in enumerate(nodes):
        kind = node.get("kind", "")
        kind_groups.setdefault(kind, []).append(i)

    # Position nodes in kind clusters initially
    kinds = list(kind_groups.keys())
    for ki, kind in enumerate(kinds):
        angle = 2 * math.pi * ki / max(len(kinds), 1)
        cx = width / 2 + math.cos(angle) * width * 0.3
        cy = height / 2 + math.sin(angle) * height * 0.3
        indices = kind_groups[kind]
        for j, idx in enumerate(indices):
            spread_angle = 2 * math.pi * j / max(len(indices), 1)
            r = min(100, len(indices) * 2)
            nodes[idx]["x"] = cx + math.cos(spread_angle) * r + (rng.random() - 0.5) * 20
            nodes[idx]["y"] = cy + math.sin(spread_angle) * r + (rng.random() - 0.5) * 20

    # Simulation parameters
    repulsion = 800.0
    attraction = 0.005
    center_pull = 0.01
    damping = 0.9
    min_dist = 5.0

    vx = [0.0] * n
    vy = [0.0] * n

    for iteration in range(iterations):
        # Temperature decreases over iterations
        temp = 1.0 - iteration / iterations
        effective_repulsion = repulsion * (0.3 + 0.7 * temp)

        # Repulsive forces (O(n^2) but fast enough for <5k nodes in Python)
        # For large graphs, only compute for nearby nodes
        fx = [0.0] * n
        fy = [0.0] * n

        if n <= 3000:
            # Full pairwise for small graphs
            for i in range(n):
                xi, yi = nodes[i]["x"], nodes[i]["y"]
                for j in range(i + 1, n):
                    dx = xi - nodes[j]["x"]
                    dy = yi - nodes[j]["y"]
                    dist_sq = dx * dx + dy * dy
                    if dist_sq < min_dist * min_dist:
                        dist_sq = min_dist * min_dist
                    if dist_sq > 500 * 500:
                        continue  # Skip very distant pairs
                    force = effective_repulsion / dist_sq
                    fdx = dx * force
                    fdy = dy * force
                    fx[i] += fdx
                    fy[i] += fdy
                    fx[j] -= fdx
                    fy[j] -= fdy
        else:
            # Grid-based approximation for large graphs
            cell_size = 100.0
            grid: dict[tuple[int, int], list[int]] = {}
            for i in range(n):
                gx = int(nodes[i]["x"] / cell_size)
                gy = int(nodes[i]["y"] / cell_size)
                grid.setdefault((gx, gy), []).append(i)

            for i in range(n):
                xi, yi = nodes[i]["x"], nodes[i]["y"]
                gx = int(xi / cell_size)
                gy = int(yi / cell_size)
                for dx_c in range(-2, 3):
                    for dy_c in range(-2, 3):
                        cell = grid.get((gx + dx_c, gy + dy_c))
                        if not cell:
                            continue
                        for j in cell:
                            if j <= i:
                                continue
                            dx = xi - nodes[j]["x"]
                            dy = yi - nodes[j]["y"]
                            dist_sq = dx * dx + dy * dy
                            if dist_sq < min_dist * min_dist:
                                dist_sq = min_dist * min_dist
                            force = effective_repulsion / dist_sq
                            fdx = dx * force
                            fdy = dy * force
                            fx[i] += fdx
                            fy[i] += fdy
                            fx[j] -= fdx
                            fy[j] -= fdy

        # Attractive forces along edges
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

        # Centering force
        for i in range(n):
            fx[i] += (width / 2 - nodes[i]["x"]) * center_pull
            fy[i] += (height / 2 - nodes[i]["y"]) * center_pull

        # Apply forces with damping
        max_displacement = 50.0 * temp + 1.0
        for i in range(n):
            vx[i] = (vx[i] + fx[i]) * damping
            vy[i] = (vy[i] + fy[i]) * damping
            # Clamp displacement
            disp = math.sqrt(vx[i] * vx[i] + vy[i] * vy[i])
            if disp > max_displacement:
                scale = max_displacement / disp
                vx[i] *= scale
                vy[i] *= scale
            nodes[i]["x"] += vx[i]
            nodes[i]["y"] += vy[i]

    # Clamp and round positions to viewport
    margin = 50.0
    for node in nodes:
        node["x"] = round(max(margin, min(width - margin, node["x"])), 1)
        node["y"] = round(max(margin, min(height - margin, node["y"])), 1)
