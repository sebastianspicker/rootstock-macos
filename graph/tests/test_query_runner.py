from __future__ import annotations

from unittest import TestCase

from query_runner import cmd_run, graph_completeness


checks = TestCase()


class FakeResult:
    def __init__(self, row):
        self.row = row

    def single(self):
        return self.row


class FakeSession:
    def __init__(self, metadata):
        self.metadata = metadata

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, *_args, **_kwargs):
        return FakeResult(self.metadata)


class FakeDriver:
    def __init__(self, metadata):
        self.metadata = metadata

    def session(self):
        return FakeSession(self.metadata)


class RaisingSession:
    def __init__(self, exc):
        self.exc = exc

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, *_args, **_kwargs):
        raise self.exc


def critical_query():
    return {
        "id": "01",
        "filename": "01-fixture.cypher",
        "path": None,
        "cypher": "MATCH (n) RETURN n",
        "name": "Critical fixture",
        "purpose": "",
        "category": "Red Team",
        "severity": "Critical",
        "parameters": "none",
        "cve": "",
        "mitre_attack": "",
    }


def test_graph_completeness_requires_clean_import_metadata():
    complete, reason = graph_completeness(
        FakeSession(
            {
                "import_status": "complete",
                "collection_error_count": 0,
                "tcc_grants_skipped": 0,
            }
        )
    )

    checks.assertIs(complete, True)
    checks.assertEqual(reason, "")


def test_graph_completeness_reports_partial_reasons():
    complete, reason = graph_completeness(
        FakeSession(
            {
                "import_status": "partial",
                "collection_error_count": 2,
                "tcc_grants_skipped": 1,
            }
        )
    )

    checks.assertIs(complete, False)
    checks.assertIn("import_status=partial", reason)
    checks.assertIn("collection_errors=2", reason)
    checks.assertIn("tcc_grants_skipped=1", reason)


def test_graph_completeness_does_not_hide_internal_errors():
    with checks.assertRaises(RuntimeError):
        graph_completeness(RaisingSession(RuntimeError("broken metadata helper")))


def test_cmd_run_does_not_hide_internal_query_errors(monkeypatch):
    def broken_run_query(*_args, **_kwargs):
        raise RuntimeError("broken export")

    monkeypatch.setattr("query_runner.run_query", broken_run_query)

    with checks.assertRaises(RuntimeError):
        cmd_run(
            FakeDriver(
                {
                    "import_status": "complete",
                    "collection_error_count": 0,
                    "tcc_grants_skipped": 0,
                }
            ),
            [critical_query()],
            "01",
            {},
            "table",
        )


def test_graph_completeness_handles_neo4j_metadata_errors():
    from neo4j.exceptions import Neo4jError

    complete, reason = graph_completeness(RaisingSession(Neo4jError("metadata down")))

    checks.assertIs(complete, False)
    checks.assertIn("metadata unavailable", reason)


def test_cmd_run_handles_neo4j_query_errors(monkeypatch):
    from neo4j.exceptions import Neo4jError

    def failing_run_query(*_args, **_kwargs):
        raise Neo4jError("query down")

    monkeypatch.setattr("query_runner.run_query", failing_run_query)

    exit_code = cmd_run(
        FakeDriver(
            {
                "import_status": "complete",
                "collection_error_count": 0,
                "tcc_grants_skipped": 0,
            }
        ),
        [critical_query()],
        "01",
        {},
        "table",
    )

    checks.assertEqual(exit_code, 1)


def test_empty_critical_query_is_not_positive_when_import_is_partial(
    monkeypatch, capsys
):
    monkeypatch.setattr("query_runner.run_query", lambda *_args, **_kwargs: [])

    exit_code = cmd_run(
        FakeDriver(
            {
                "import_status": "partial",
                "collection_error_count": 1,
                "tcc_grants_skipped": 0,
            }
        ),
        [critical_query()],
        "01",
        {},
        "table",
    )

    output = capsys.readouterr().out
    checks.assertEqual(exit_code, 0)
    checks.assertIn("No rows returned; graph completeness not verified", output)
    checks.assertNotIn("positive security result", output)


def test_empty_critical_query_can_be_positive_when_import_is_complete(
    monkeypatch, capsys
):
    monkeypatch.setattr("query_runner.run_query", lambda *_args, **_kwargs: [])

    exit_code = cmd_run(
        FakeDriver(
            {
                "import_status": "complete",
                "collection_error_count": 0,
                "tcc_grants_skipped": 0,
            }
        ),
        [critical_query()],
        "01",
        {},
        "table",
    )

    output = capsys.readouterr().out
    checks.assertEqual(exit_code, 0)
    checks.assertIn("positive security result", output)
