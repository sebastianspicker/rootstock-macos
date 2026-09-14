"""Deterministic Barnes–Hut repulsion with an exact interaction boundary."""

from __future__ import annotations

import math


class _Cell:
    __slots__ = (
        "left",
        "top",
        "right",
        "bottom",
        "mass",
        "x",
        "y",
        "children",
        "members",
        "size_squared",
        "outer",
        "inner",
    )

    def __init__(self, points, members, depth=0):
        self.left = min(points[i][0] for i in members)
        self.right = max(points[i][0] for i in members)
        self.top = min(points[i][1] for i in members)
        self.bottom = max(points[i][1] for i in members)
        self.mass = len(members)
        self.x = sum(points[i][0] for i in members) / self.mass
        self.y = sum(points[i][1] for i in members) / self.mass
        radius = math.hypot(
            max(self.x - self.left, self.right - self.x),
            max(self.y - self.top, self.bottom - self.y),
        )
        self.outer = (500 + radius) ** 2
        self.inner = (500 - radius) ** 2 if radius <= 500 else -1
        self.size_squared = max(self.right - self.left, self.bottom - self.top) ** 2
        self.children = []
        self.members = members
        # Coincident points remain one bounded leaf; no arbitrary jitter is added.
        if (
            len(members) <= 8
            or depth >= 20
            or (self.left == self.right and self.top == self.bottom)
        ):
            return
        mid_x = (self.left + self.right) / 2
        mid_y = (self.top + self.bottom) / 2
        groups = [[], [], [], []]
        for i in members:
            x, y = points[i]
            groups[int(x >= mid_x) + 2 * int(y >= mid_y)].append(i)
        self.children = [_Cell(points, group, depth + 1) for group in groups if group]
        self.members = []


def _can_approximate(cell, x, y, distance_squared):
    return (
        cell.size_squared < 0.49 * distance_squared
        and distance_squared <= cell.inner
        and not (cell.left <= x <= cell.right and cell.top <= y <= cell.bottom)
    )


def _force(points, index, root, strength, minimum_squared):
    x, y = points[index]
    force_x = force_y = 0.0
    stack = [root]
    while stack:
        cell = stack.pop()
        dx, dy = x - cell.x, y - cell.y
        distance_squared = dx * dx + dy * dy
        if distance_squared > cell.outer:
            continue
        # Never approximate a cell straddling the 500-unit cutoff or containing self.
        if _can_approximate(cell, x, y, distance_squared):
            factor = strength * cell.mass / max(distance_squared, minimum_squared)
            force_x += dx * factor
            force_y += dy * factor
        elif cell.children:
            stack.extend(reversed(cell.children))
        else:
            fx, fy = _leaf_force(points, cell, index, strength, minimum_squared)
            force_x += fx
            force_y += fy
    return force_x, force_y


def _leaf_force(points, cell, index, strength, minimum_squared):
    x, y = points[index]
    fx = fy = 0.0
    if cell.left == cell.right and cell.top == cell.bottom:
        dx, dy = x - cell.x, y - cell.y
        distance_squared = dx * dx + dy * dy
        if distance_squared > 250_000:
            return 0.0, 0.0
        factor = strength * cell.mass / max(distance_squared, minimum_squared)
        return dx * factor, dy * factor
    for other in cell.members:
        if other == index:
            continue
        dx, dy = x - points[other][0], y - points[other][1]
        distance_squared = dx * dx + dy * dy
        if distance_squared <= 250_000:
            factor = strength / max(distance_squared, minimum_squared)
            fx += dx * factor
            fy += dy * factor
    return fx, fy


def apply_tree_repulsion(nodes, fx, fy, strength, min_dist):
    """Accumulate bounded repulsion; traversal and subdivision follow input order."""
    if not nodes:
        return
    points = [(node["x"], node["y"]) for node in nodes]
    root = _Cell(points, list(range(len(points))))
    for i in range(len(points)):
        dx, dy = _force(points, i, root, strength, math.pow(min_dist, 2))
        fx[i] += dx
        fy[i] += dy
