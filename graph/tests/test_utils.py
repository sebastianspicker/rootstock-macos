"""test_utils.py — Tests for graph/utils.py helper functions."""

from __future__ import annotations

from unittest.mock import MagicMock

from utils import first_cypher_statement, list_or_str, run_query, sanitize_id, truncate, validate_read_only_cypher


# ── list_or_str ──────────────────────────────────────────────────────────────

def test_list_or_str_with_list():
    assert list_or_str(["a", "b", "c"]) == "a, b, c"


def test_list_or_str_with_none():
    assert list_or_str(None) == "—"


def test_list_or_str_with_custom_placeholder():
    assert list_or_str(None, none_placeholder="N/A") == "N/A"


def test_list_or_str_with_string():
    assert list_or_str("hello") == "hello"


def test_list_or_str_with_int():
    assert list_or_str(42) == "42"


# ── truncate ─────────────────────────────────────────────────────────────────

def test_truncate_short_unchanged():
    assert truncate("short", max_len=30) == "short"


def test_truncate_exact_length():
    text = "x" * 30
    assert truncate(text, max_len=30) == text


def test_truncate_over_length():
    text = "a" * 40
    result = truncate(text, max_len=30)
    assert len(result) == 30
    assert result.endswith("…")


# ── sanitize_id ──────────────────────────────────────────────────────────────

def test_sanitize_id_alphanums_unchanged():
    assert sanitize_id("abc_123") == "abc_123"


def test_sanitize_id_special_chars():
    assert sanitize_id("com.apple.Terminal") == "com_apple_Terminal"


def test_sanitize_id_empty_returns_fallback():
    assert sanitize_id("") == "node"
    assert sanitize_id("", fallback="unknown") == "unknown"


# ── first_cypher_statement ───────────────────────────────────────────────────

def test_first_cypher_strips_comments():
    cypher = "// comment\nMATCH (n) RETURN n;\nMATCH (m) RETURN m;"
    assert first_cypher_statement(cypher) == "MATCH (n) RETURN n"


def test_first_cypher_returns_first_nonempty():
    cypher = "  ;  ; MATCH (n) RETURN n"
    assert first_cypher_statement(cypher) == "MATCH (n) RETURN n"


def test_first_cypher_no_semicolons():
    cypher = "MATCH (n) RETURN n"
    assert first_cypher_statement(cypher) == "MATCH (n) RETURN n"


# ── run_query ────────────────────────────────────────────────────────────────

def test_run_query_returns_dicts():
    record1 = {"name": "iTerm2", "count": 1}
    record2 = {"name": "Slack", "count": 2}
    mock_session = MagicMock()
    mock_session.run.return_value = [record1, record2]

    result = run_query(mock_session, "MATCH (n) RETURN n.name AS name")
    assert result == [record1, record2]
    mock_session.run.assert_called_once_with("MATCH (n) RETURN n.name AS name", {})


# ── validate_read_only_cypher ───────────────────────────────────────────────

def test_validate_match_is_safe():
    assert validate_read_only_cypher("MATCH (n) RETURN n") is None


def test_validate_return_is_safe():
    assert validate_read_only_cypher("RETURN 1 + 1") is None


def test_validate_create_rejected():
    result = validate_read_only_cypher("CREATE (n:Test)")
    assert result is not None
    assert "CREATE" in result


def test_validate_merge_rejected():
    result = validate_read_only_cypher("MERGE (n:Test {id: 1})")
    assert result is not None
    assert "MERGE" in result


def test_validate_set_rejected():
    result = validate_read_only_cypher("MATCH (n) SET n.name = 'x'")
    assert result is not None
    assert "SET" in result


def test_validate_delete_rejected():
    result = validate_read_only_cypher("MATCH (n) DELETE n")
    assert result is not None
    assert "DELETE" in result


def test_validate_remove_rejected():
    result = validate_read_only_cypher("MATCH (n) REMOVE n.name")
    assert result is not None
    assert "REMOVE" in result


def test_validate_drop_rejected():
    result = validate_read_only_cypher("DROP INDEX my_index")
    assert result is not None
    assert "DROP" in result


def test_validate_detach_rejected():
    result = validate_read_only_cypher("MATCH (n) DETACH DELETE n")
    assert result is not None


def test_validate_case_insensitive():
    assert validate_read_only_cypher("create (n:Test)") is not None
    assert validate_read_only_cypher("MeRgE (n:Test)") is not None


def test_validate_create_in_string_literal():
    """'CREATE' inside a string literal should NOT be rejected."""
    assert validate_read_only_cypher("MATCH (n) WHERE n.name = 'CREATE' RETURN n") is None


def test_validate_comments_stripped():
    """Comments should be stripped before validation."""
    assert validate_read_only_cypher("// CREATE node\nMATCH (n) RETURN n") is None


def test_validate_complex_read_query():
    """Complex read queries with WITH, UNWIND, etc. should pass."""
    query = """
        MATCH (app:Application)-[:HAS_TCC_GRANT]->(tcc:TCC_Permission)
        WITH app, collect(tcc.service) AS services
        UNWIND services AS svc
        RETURN app.name, svc
    """
    assert validate_read_only_cypher(query) is None


def test_validate_load_csv_rejected():
    """LOAD CSV is a write/import operation and must be blocked."""
    assert validate_read_only_cypher("LOAD CSV FROM 'file:///x' AS row CREATE (n)") is not None


def test_validate_foreach_rejected():
    """FOREACH can mutate graph state and must be blocked."""
    query = "MATCH p=(n)-[*]->(m) FOREACH (x IN nodes(p) | SET x.visited = true)"
    assert validate_read_only_cypher(query) is not None


def test_validate_bare_call_rejected():
    """Bare CALL (not to db./dbms./apoc.) should be blocked."""
    assert validate_read_only_cypher("CALL custom.procedure()") is not None


def test_validate_call_db_safe():
    """CALL db.* and CALL dbms.* are safe read-only procedures."""
    assert validate_read_only_cypher("CALL db.labels()") is None
    assert validate_read_only_cypher("CALL dbms.listConfig()") is None


def test_validate_call_apoc_safe():
    """CALL apoc.* is generally safe for read operations."""
    assert validate_read_only_cypher("CALL apoc.meta.schema()") is None


def test_validate_load_csv_case_insensitive():
    """LOAD CSV bypass should be case-insensitive."""
    assert validate_read_only_cypher("load csv FROM 'x' AS row") is not None


# ── safe_count ────────────────────────────────────────────────────────────

from utils import safe_count  # noqa: E402


def test_safe_count_normal():
    mock_result = MagicMock()
    mock_result.single.return_value = {"n": 42}
    assert safe_count(mock_result) == 42


def test_safe_count_none_result():
    mock_result = MagicMock()
    mock_result.single.return_value = None
    assert safe_count(mock_result) == 0


def test_safe_count_none_value():
    mock_result = MagicMock()
    mock_result.single.return_value = {"n": None}
    assert safe_count(mock_result) == 0
