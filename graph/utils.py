"""
utils.py - Shared utilities for Rootstock graph tools.

Common helpers used by report.py, query_runner.py, report_diagrams.py,
and report_graphviz.py to avoid duplication.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from neo4j import Query


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


def list_or_str(value: Any, none_placeholder: str = " - ") -> str:
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


class _CypherCommentStripper:
    def __init__(self) -> None:
        self.output: list[str] = []
        self.quote: str | None = None
        self.escaped = False

    def consume(self, cypher: str, index: int) -> int:
        char = cypher[index]
        if self.quote is not None:
            return self.consume_quoted(cypher, index)
        if char in ("'", '"', "`"):
            self.quote = char
            self.output.append(char)
            return index + 1
        if cypher.startswith("//", index):
            return self.consume_line_comment(cypher, index)
        if cypher.startswith("/*", index):
            return self.consume_block_comment(cypher, index)
        self.output.append(char)
        return index + 1

    def consume_quoted(self, cypher: str, index: int) -> int:
        char = cypher[index]
        following = cypher[index + 1] if index + 1 < len(cypher) else ""
        self.output.append(char)
        if self._continues_escaped_backtick(char, following):
            self.output.append(following)
            return index + 2
        self._update_quoted_state(char)
        return index + 1

    def _continues_escaped_backtick(self, char: str, following: str) -> bool:
        return self.quote == "`" and char == "`" and following == "`"

    def _update_quoted_state(self, char: str) -> None:
        if self.escaped:
            self.escaped = False
        elif char == "\\" and self.quote != "`":
            self.escaped = True
        elif char == self.quote:
            self.quote = None

    def consume_line_comment(self, cypher: str, index: int) -> int:
        line_end = index + 2
        while line_end < len(cypher) and cypher[line_end] not in "\r\n":
            line_end += 1
        self.output.append(" ")
        return line_end

    def consume_block_comment(self, cypher: str, index: int) -> int:
        comment_end = cypher.find("*/", index + 2)
        if comment_end < 0:
            self.output.append(cypher[index:])
            return len(cypher)
        self.output.append(" ")
        self.output.extend(char for char in cypher[index + 2 : comment_end] if char in "\r\n")
        return comment_end + 2


def _strip_cypher_comments(cypher: str) -> str:
    """Remove comments without changing quoted text or statement line structure."""
    stripper = _CypherCommentStripper()
    index = 0
    while index < len(cypher):
        index = stripper.consume(cypher, index)
    return "".join(stripper.output)


def cypher_code_only(cypher: str) -> str:
    """Remove comments, quoted strings, and escaped identifiers for policy checks."""
    cleaned = _strip_cypher_comments(cypher)
    cleaned = re.sub(r"'(?:[^'\\]|\\.)*'", "''", cleaned)
    cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', '""', cleaned)
    return re.sub(r"`(?:[^`]|``)*`", "``", cleaned)


def run_query(
    session,
    cypher: str | Query,
    params: dict | None = None,
    *,
    maximum_rows: int | None = None,
) -> list[dict]:
    """Run one Cypher statement with an optional client-side row bound."""
    result = session.run(cypher, params or {})
    rows = []
    for record in result:
        if maximum_rows is not None and len(rows) >= maximum_rows:
            break
        rows.append(dict(record))
    return rows


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
    r"CREATE|INSERT|MERGE|SET|DELETE|REMOVE|DROP|DETACH"
    r"|ALTER|RENAME|GRANT|DENY|REVOKE|TERMINATE"
    r"|START\s+DATABASE|STOP\s+DATABASE"
    r"|ENABLE\s+SERVER|DEALLOCATE\s+DATABASES?|REALLOCATE\s+DATABASES?"
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
    match = _WRITE_KEYWORDS.search(cypher_code_only(cypher))
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
