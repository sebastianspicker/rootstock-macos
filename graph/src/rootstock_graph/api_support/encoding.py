"""JSON-safe conversion of Neo4j driver values for API responses."""

from __future__ import annotations

from typing import Any

from neo4j.graph import Node, Path, Relationship
from neo4j.spatial import Point
from neo4j.time import Date, DateTime, Duration, Time


def jsonable(value: Any) -> Any:
    """Recursively convert Neo4j graph, temporal and spatial values to plain JSON types."""
    if isinstance(value, Node):
        return {"labels": sorted(value.labels), "properties": jsonable(dict(value))}
    if isinstance(value, Relationship):
        return {
            "type": value.type,
            "start": value.start_node.element_id,
            "end": value.end_node.element_id,
            "properties": jsonable(dict(value)),
        }
    if isinstance(value, Path):
        return {
            "nodes": [jsonable(node) for node in value.nodes],
            "relationships": [jsonable(relationship) for relationship in value.relationships],
        }
    if isinstance(value, DateTime | Date | Time | Duration):
        return value.iso_format()
    if isinstance(value, Point):
        return str(value)
    if isinstance(value, dict):
        return {key: jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [jsonable(item) for item in value]
    return value
