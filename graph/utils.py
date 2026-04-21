"""
utils.py — Shared utilities for Rootstock graph tools.

Common helpers used by report.py, query_runner.py, report_diagrams.py,
and report_graphviz.py to avoid duplication.
"""

from __future__ import annotations

import re
from typing import Any


def list_or_str(value: Any, none_placeholder: str = "—") -> str:
    """Convert list values from Neo4j to a comma-separated string."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if value is None:
        return none_placeholder
    return str(value)


def first_cypher_statement(cypher: str) -> str:
    """
    Extract the first executable Cypher statement from a multi-statement file.
    Strips comment lines first, then splits on semicolons.
    """
    non_comment_lines = [
        line for line in cypher.splitlines() if not line.strip().startswith("//")
    ]
    cleaned = "\n".join(non_comment_lines)
    for stmt in cleaned.split(";"):
        stripped = stmt.strip()
        if stripped:
            return stripped
    return cleaned.strip()


def run_query(session, cypher: str, params: dict | None = None) -> list[dict]:
    """Run a single Cypher statement, return list of record dicts."""
    result = session.run(cypher, params or {})
    return [dict(r) for r in result]


def sanitize_id(text: str, fallback: str = "node") -> str:
    """Convert arbitrary strings to safe identifiers (alphanumeric + underscore)."""
    if not text:
        return fallback
    return re.sub(r"[^a-zA-Z0-9_]", "_", str(text))


def truncate(text: str, max_len: int = 30) -> str:
    """Truncate long labels for diagram readability."""
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


# ── Read-only Cypher validation ─────────────────────────────────────────────

_WRITE_KEYWORDS = re.compile(
    r"\b("
    r"CREATE|MERGE|SET|DELETE|REMOVE|DROP|DETACH"
    r"|LOAD\s+CSV"
    r"|FOREACH"
    r"|CALL\s*\{"
    r"|CALL\s+(?!db\.|dbms\.|apoc\.meta\.|apoc\.help|apoc\.coll\.|apoc\.text\.|apoc\.convert\.)"
    r")\b",
    re.IGNORECASE,
)


def validate_read_only_cypher(cypher: str) -> str | None:
    """
    Check that a Cypher query is read-only.

    Returns None if the query is safe, or an error message string
    describing the rejected keyword if a write operation is detected.

    Strips comments before checking.
    """
    # Strip // comments
    lines = [line for line in cypher.splitlines() if not line.strip().startswith("//")]
    cleaned = " ".join(lines)

    # Strip block comments /* ... */
    cleaned = re.sub(r"/\*.*?\*/", " ", cleaned, flags=re.DOTALL)

    # Strip string literals to avoid false positives
    # (e.g., "SET something" as a string value)
    # Handle backslash-escaped quotes to prevent bypass via e.g. 'a\'' CREATE ...'
    no_strings = re.sub(r"'(?:[^'\\]|\\.)*'", "''", cleaned)
    no_strings = re.sub(r'"(?:[^"\\]|\\.)*"', '""', no_strings)

    match = _WRITE_KEYWORDS.search(no_strings)
    if match:
        return f"Write operation not allowed: {match.group(0).strip()}"
    return None


def safe_count(result) -> int:
    """Extract count from a Neo4j result, returning 0 if the result is empty or None.

    Safely handles the common pattern of ``result.single()["n"]`` where
    ``single()`` may return ``None`` (empty result set) or the value itself
    may be ``None``.
    """
    row = result.single()
    if row is None:
        return 0
    value = row.get("n") if hasattr(row, "get") else row["n"]
    return int(value) if value is not None else 0


def batched_unwind(
    session, cypher: str, records: list[dict], *, batch_size: int = 500
) -> int:
    """Execute a Cypher UNWIND query in batches, returning the total count.

    Splits *records* into chunks of *batch_size* and runs *cypher* (which must
    use ``UNWIND $batch AS row ... RETURN count(*) AS n``) once per chunk.
    This prevents Neo4j transaction-size pressure for large imports.
    """
    total = 0
    for i in range(0, len(records), batch_size):
        chunk = records[i : i + batch_size]
        result = session.run(cypher, batch=chunk)
        total += safe_count(result)
    return total
