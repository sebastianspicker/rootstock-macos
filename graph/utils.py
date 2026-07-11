"""
utils.py — Shared utilities for Rootstock graph tools.

Common helpers used by report.py, query_runner.py, report_diagrams.py,
and report_graphviz.py to avoid duplication.
"""

from __future__ import annotations

import re
from typing import Any


class _CypherStatementScanner:
    def __init__(self) -> None:
        self.quote: str | None = None
        self.escaped = False

    def consume_quoted_char(self, char: str) -> bool:
        if self.escaped:
            self.escaped = False
            return True
        if self.quote is None:
            return False
        if char == "\\":
            self.escaped = True
        elif char == self.quote:
            self.quote = None
        return True

    def consume(self, char: str) -> bool:
        if self.consume_quoted_char(char):
            return True
        if char in ("'", '"'):
            self.quote = char
            return True
        return False


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
    Strips comment lines first, then splits on semicolons outside strings.
    """
    cleaned = _strip_cypher_comments(cypher)
    start = 0
    scanner = _CypherStatementScanner()

    for index, char in enumerate(cleaned):
        if scanner.consume(char):
            continue
        if char == ";":
            stripped = cleaned[start:index].strip()
            if stripped:
                return stripped
            start = index + 1

    return cleaned[start:].strip()


def _strip_cypher_comments(cypher: str) -> str:
    no_line_comments = "\n".join(
        line for line in cypher.splitlines() if not line.strip().startswith("//")
    )
    parts: list[str] = []
    cursor = 0
    while (comment_start := no_line_comments.find("/*", cursor)) >= 0:
        comment_end = no_line_comments.find("*/", comment_start + 2)
        if comment_end < 0:
            break
        parts.append(no_line_comments[cursor:comment_start])
        parts.append(" ")
        cursor = comment_end + 2
    parts.append(no_line_comments[cursor:])
    return "".join(parts)


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
    cleaned = _strip_cypher_comments(cypher)

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
