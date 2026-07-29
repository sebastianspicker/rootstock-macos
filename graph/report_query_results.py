"""Shared normalization for graph-query result collections."""

from __future__ import annotations


def query_rows(
    query_results: dict[str, list[dict] | str], filename: str
) -> list[dict]:
    """Return rows for a successful query, treating errors as no rows."""
    result = query_results.get(filename, [])
    return result if isinstance(result, list) else []
