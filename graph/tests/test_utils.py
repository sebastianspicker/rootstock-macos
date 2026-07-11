"""test_utils.py — Tests for graph/utils.py helper functions."""

from __future__ import annotations

from unittest import TestCase
from unittest.mock import MagicMock

from utils import (
    first_cypher_statement,
    list_or_str,
    run_query,
    sanitize_id,
    truncate,
    validate_read_only_cypher,
)


# ── list_or_str ──────────────────────────────────────────────────────────────

checks = TestCase()


def test_list_or_str_with_list():
    checks.assertEqual(list_or_str(["a", "b", "c"]), "a, b, c")


def test_list_or_str_with_none():
    checks.assertEqual(list_or_str(None), "—")


def test_list_or_str_with_custom_placeholder():
    checks.assertEqual(list_or_str(None, none_placeholder="N/A"), "N/A")


def test_list_or_str_with_string():
    checks.assertEqual(list_or_str("hello"), "hello")


def test_list_or_str_with_int():
    checks.assertEqual(list_or_str(42), "42")


# ── truncate ─────────────────────────────────────────────────────────────────


def test_truncate_short_unchanged():
    checks.assertEqual(truncate("short", max_len=30), "short")


def test_truncate_exact_length():
    text = "x" * 30
    checks.assertEqual(truncate(text, max_len=30), text)


def test_truncate_over_length():
    text = "a" * 40
    result = truncate(text, max_len=30)
    checks.assertEqual(len(result), 30)
    checks.assertTrue(result.endswith("…"))


# ── sanitize_id ──────────────────────────────────────────────────────────────


def test_sanitize_id_alphanums_unchanged():
    checks.assertEqual(sanitize_id("abc_123"), "abc_123")


def test_sanitize_id_special_chars():
    checks.assertEqual(sanitize_id("com.apple.Terminal"), "com_apple_Terminal")


def test_sanitize_id_empty_returns_fallback():
    checks.assertEqual(sanitize_id(""), "node")
    checks.assertEqual(sanitize_id("", fallback="unknown"), "unknown")


# ── first_cypher_statement ───────────────────────────────────────────────────


def test_first_cypher_strips_comments():
    cypher = "// comment\nMATCH (n) RETURN n;\nMATCH (m) RETURN m;"
    checks.assertEqual(first_cypher_statement(cypher), "MATCH (n) RETURN n")


def test_first_cypher_strips_block_comments_before_splitting():
    cypher = "/* ignored ; comment */ MATCH (n) RETURN n; MATCH (m) RETURN m"

    checks.assertEqual(first_cypher_statement(cypher), "MATCH (n) RETURN n")


def test_first_cypher_preserves_unterminated_block_comment():
    cypher = "MATCH (n) RETURN n /*" + "a/*" * 10_000

    checks.assertEqual(first_cypher_statement(cypher), cypher)


def test_first_cypher_returns_first_nonempty():
    cypher = "  ;  ; MATCH (n) RETURN n"
    checks.assertEqual(first_cypher_statement(cypher), "MATCH (n) RETURN n")


def test_first_cypher_no_semicolons():
    cypher = "MATCH (n) RETURN n"
    checks.assertEqual(first_cypher_statement(cypher), "MATCH (n) RETURN n")


def test_first_cypher_preserves_single_quoted_semicolon():
    cypher = "MATCH (n) WHERE n.name = 'alpha; beta' RETURN n; MATCH (m) RETURN m"
    checks.assertEqual(
        first_cypher_statement(cypher),
        "MATCH (n) WHERE n.name = 'alpha; beta' RETURN n",
    )


def test_first_cypher_preserves_double_quoted_semicolon():
    cypher = 'MATCH (n) WHERE n.name = "alpha; beta" RETURN n; MATCH (m) RETURN m'
    checks.assertEqual(
        first_cypher_statement(cypher),
        'MATCH (n) WHERE n.name = "alpha; beta" RETURN n',
    )


def test_first_cypher_preserves_escaped_quote_before_semicolon():
    cypher = r"MATCH (n) WHERE n.name = 'alpha\'; beta' RETURN n; MATCH (m) RETURN m"
    checks.assertEqual(
        first_cypher_statement(cypher),
        r"MATCH (n) WHERE n.name = 'alpha\'; beta' RETURN n",
    )


# ── run_query ────────────────────────────────────────────────────────────────


def test_run_query_returns_dicts():
    record1 = {"name": "iTerm2", "count": 1}
    record2 = {"name": "Slack", "count": 2}
    mock_session = MagicMock()
    mock_session.run.return_value = [record1, record2]

    result = run_query(mock_session, "MATCH (n) RETURN n.name AS name")
    checks.assertEqual(result, [record1, record2])
    mock_session.run.assert_called_once_with("MATCH (n) RETURN n.name AS name", {})


# ── validate_read_only_cypher ───────────────────────────────────────────────


def test_validate_match_is_safe():
    checks.assertIsNone(validate_read_only_cypher("MATCH (n) RETURN n"))


def test_validate_return_is_safe():
    checks.assertIsNone(validate_read_only_cypher("RETURN 1 + 1"))


def test_validate_create_rejected():
    result = validate_read_only_cypher("CREATE (n:Test)")
    checks.assertIsNotNone(result)
    checks.assertIn("CREATE", result)


def test_validate_merge_rejected():
    result = validate_read_only_cypher("MERGE (n:Test {id: 1})")
    checks.assertIsNotNone(result)
    checks.assertIn("MERGE", result)


def test_validate_set_rejected():
    result = validate_read_only_cypher("MATCH (n) SET n.name = 'x'")
    checks.assertIsNotNone(result)
    checks.assertIn("SET", result)


def test_validate_delete_rejected():
    result = validate_read_only_cypher("MATCH (n) DELETE n")
    checks.assertIsNotNone(result)
    checks.assertIn("DELETE", result)


def test_validate_remove_rejected():
    result = validate_read_only_cypher("MATCH (n) REMOVE n.name")
    checks.assertIsNotNone(result)
    checks.assertIn("REMOVE", result)


def test_validate_drop_rejected():
    result = validate_read_only_cypher("DROP INDEX my_index")
    checks.assertIsNotNone(result)
    checks.assertIn("DROP", result)


def test_validate_detach_rejected():
    result = validate_read_only_cypher("MATCH (n) DETACH DELETE n")
    checks.assertIsNotNone(result)


def test_validate_case_insensitive():
    checks.assertIsNotNone(validate_read_only_cypher("create (n:Test)"))
    checks.assertIsNotNone(validate_read_only_cypher("MeRgE (n:Test)"))


def test_validate_create_in_string_literal():
    """'CREATE' inside a string literal should NOT be rejected."""
    checks.assertIsNone(
        validate_read_only_cypher("MATCH (n) WHERE n.name = 'CREATE' RETURN n")
    )


def test_validate_comments_stripped():
    """Comments should be stripped before validation."""
    checks.assertIsNone(validate_read_only_cypher("// CREATE node\nMATCH (n) RETURN n"))


def test_validate_complex_read_query():
    """Complex read queries with WITH, UNWIND, etc. should pass."""
    query = """
        MATCH (app:Application)-[:HAS_TCC_GRANT]->(tcc:TCC_Permission)
        WITH app, collect(tcc.service) AS services
        UNWIND services AS svc
        RETURN app.name, svc
    """
    checks.assertIsNone(validate_read_only_cypher(query))


def test_validate_load_csv_rejected():
    """LOAD CSV is a write/import operation and must be blocked."""
    checks.assertIsNotNone(
        validate_read_only_cypher("LOAD CSV FROM 'file:///x' AS row CREATE (n)")
    )


def test_validate_foreach_rejected():
    """FOREACH can mutate graph state and must be blocked."""
    query = "MATCH p=(n)-[*]->(m) FOREACH (x IN nodes(p) | SET x.visited = true)"
    checks.assertIsNotNone(validate_read_only_cypher(query))


def test_validate_bare_call_rejected():
    """Bare CALL (not to db./dbms./apoc.) should be blocked."""
    checks.assertIsNotNone(validate_read_only_cypher("CALL custom.procedure()"))


def test_validate_call_db_safe():
    """CALL db.* and CALL dbms.* are safe read-only procedures."""
    checks.assertIsNone(validate_read_only_cypher("CALL db.labels()"))
    checks.assertIsNone(validate_read_only_cypher("CALL dbms.listConfig()"))


def test_validate_call_apoc_safe():
    """CALL apoc.* is generally safe for read operations."""
    checks.assertIsNone(validate_read_only_cypher("CALL apoc.meta.schema()"))


def test_validate_load_csv_case_insensitive():
    """LOAD CSV bypass should be case-insensitive."""
    checks.assertIsNotNone(validate_read_only_cypher("load csv FROM 'x' AS row"))


# ── safe_count ────────────────────────────────────────────────────────────

from utils import safe_count  # noqa: E402


def test_safe_count_normal():
    mock_result = MagicMock()
    mock_result.single.return_value = {"n": 42}
    checks.assertEqual(safe_count(mock_result), 42)


def test_safe_count_none_result():
    mock_result = MagicMock()
    mock_result.single.return_value = None
    checks.assertEqual(safe_count(mock_result), 0)


def test_safe_count_none_value():
    mock_result = MagicMock()
    mock_result.single.return_value = {"n": None}
    checks.assertEqual(safe_count(mock_result), 0)
