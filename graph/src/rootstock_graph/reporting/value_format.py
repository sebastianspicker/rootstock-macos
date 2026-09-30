"""Plain-text formatting of Neo4j result values for tables, CSV, and reports."""

from __future__ import annotations

from typing import Any


def list_or_str(value: Any, none_placeholder: str = " - ") -> str:
    """Convert list values from Neo4j to a comma-separated string."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if value is None:
        return none_placeholder
    return str(value)
