"""Report downloads preserve authentication, read routing and bounded failure semantics."""

from __future__ import annotations

import pytest
from neo4j import READ_ACCESS
from neo4j.exceptions import ServiceUnavailable

from test_api_security import AUTH, FakeResult, api_client as api_client
from rootstock_graph.api_support import reports


@pytest.fixture
def report_catalog(monkeypatch):
    monkeypatch.setattr(
        reports,
        "discover_queries",
        lambda: [{"filename": "01-example.cypher", "cypher": "MATCH (n) RETURN n"}],
    )


def test_report_requires_authentication_before_format_validation(api_client):
    client, writer, reader, _session = api_client
    response = client.post("/api/report", json={"format": "pdf"})
    assert response.status_code == 401
    assert writer.access_modes == reader.access_modes == []


@pytest.mark.parametrize(
    "format,extension,media_type",
    [
        ("markdown", "md", "text/markdown"),
        ("html", "html", "text/html"),
    ],
)
def test_report_uses_read_principal_and_existing_assembly(
    api_client, report_catalog, monkeypatch, format, extension, media_type
):
    client, writer, reader, session = api_client
    assembled = []

    def assemble(rows, metadata):
        assembled.append((rows, metadata))
        return "# Assessment\n\nSynthetic finding."

    monkeypatch.setattr(reports, "assemble_report", assemble)
    response = client.post("/api/report", headers=AUTH, json={"format": format})
    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == f"rootstock-assessment.{extension}"
    assert body["media_type"] == media_type
    assert "Synthetic finding." in body["content"]
    assert "current loaded graph" in body["content"]
    assert assembled[0][0] == {"01-example.cypher": session.rows}
    assert assembled[0][1]["hostname"] == "Unknown"
    assert assembled[0][1]["timestamp"] == "Unknown"
    assert writer.access_modes == []
    assert reader.access_modes == [READ_ACCESS]
    assert session.begin_transactions == 0
    assert all(0 < query.timeout <= 5 for query in session.queries)
    assert response.headers["cache-control"] == "no-store"


def test_report_metadata_renders_as_semantic_html():
    from rootstock_graph.reporting.report_assembly import _append_scan_metadata
    from rootstock_graph.reporting.report_html import markdown_to_html

    sections = []
    _append_scan_metadata(sections, {"hostname": "Synthetic host"}, "Unknown")
    html = markdown_to_html("\n\n".join(sections))
    assert "<th>Field</th>" in html
    assert "<th>Value</th>" in html
    assert "<td>Hostname</td>" in html
    assert "<td>Synthetic host</td>" in html


def test_html_report_makes_untrusted_links_images_and_raw_html_inert():
    from rootstock_graph.reporting.report_html import markdown_to_html

    html = markdown_to_html(
        "# Evidence\n\n[click](javascript:alert(1)) "
        "![beacon](https://attacker.example/collect) "
        "<script>alert(2)</script><iframe src=https://attacker.example></iframe>"
    )

    assert "javascript:" not in html
    assert "attacker.example" not in html
    assert "<img" not in html
    assert "<script" not in html
    assert "<iframe" not in html
    assert "<a>click</a>" in html
    assert "default-src 'none'" in html


@pytest.mark.parametrize(
    "body",
    [
        {"format": "pdf"},
        {"format": "html", "output": "/tmp/report.html"},
        {"format": "markdown", "scan_json": "/private/scan.json"},
        {"format": "markdown", "cypher": "CREATE (n)"},
    ],
)
def test_report_rejects_unsupported_formats_and_server_inputs(api_client, body):
    client, _writer, _reader, session = api_client
    response = client.post("/api/report", headers=AUTH, json=body)
    assert response.status_code == 422
    assert session.queries == []


def test_report_fails_without_partial_download_on_database_failure(api_client, report_catalog):
    client, _writer, _reader, session = api_client
    session.failure = ServiceUnavailable("secret-password at private-host")
    response = client.post("/api/report", headers=AUTH, json={})
    assert response.status_code == 503
    assert "content" not in response.json()
    assert "secret-password" not in response.text
    assert "private-host" not in response.text


def test_report_rejects_truncated_results(api_client, report_catalog, monkeypatch):
    client, _writer, _reader, session = api_client
    monkeypatch.setattr(reports, "MAX_QUERY_ROWS", 2)
    session.rows = [{"n": 1}, {"n": 2}, {"n": 3}]
    response = client.post("/api/report", headers=AUTH, json={})
    assert response.status_code == 413
    assert "content" not in response.json()


def test_report_enforces_total_rows_and_download_bytes(api_client, report_catalog, monkeypatch):
    client, _writer, _reader, _session = api_client
    monkeypatch.setattr(reports, "MAX_TOTAL_ROWS", 0)
    assert client.post("/api/report", headers=AUTH, json={}).status_code == 413
    monkeypatch.setattr(reports, "MAX_TOTAL_ROWS", 20_000)
    monkeypatch.setattr(reports, "MAX_REPORT_BYTES", 1)
    assert client.post("/api/report", headers=AUTH, json={}).status_code == 413


def test_report_rejects_write_queries_in_catalog(api_client, monkeypatch):
    client, _writer, _reader, session = api_client
    monkeypatch.setattr(
        reports,
        "discover_queries",
        lambda: [
            {"filename": "invalid.cypher", "cypher": "CREATE (n)"},
        ],
    )
    response = client.post("/api/report", headers=AUTH, json={})
    assert response.status_code == 500
    assert all("CREATE" not in str(query) for query in session.queries)


def test_report_enforces_request_time_budget(api_client, monkeypatch):
    client, _writer, _reader, session = api_client
    monkeypatch.setattr(reports, "REPORT_TIMEOUT_SECONDS", 0)
    response = client.post("/api/report", headers=AUTH, json={})
    assert response.status_code == 504
    assert session.queries == []


def test_report_retains_partial_import_metadata(api_client, report_catalog, monkeypatch):
    client, _writer, _reader, session = api_client

    def run(query, *_args, **_kwargs):
        text = str(query)
        if "c.scan_id AS scan_id" in text:
            assert "c.import_status AS import_status" in text
            assert "c.collection_error_sources AS collection_error_sources" in text
            return FakeResult(
                [
                    {
                        "hostname": "synthetic-host",
                        "import_status": "partial",
                        "collection_error_count": 1,
                        "collection_error_sources": ["TCC"],
                        "tcc_grants_skipped": 2,
                    }
                ]
            )
        if "AS scans" in text:
            return FakeResult([{"scans": 1, "known": 1, "errors": 1, "skipped": 2}])
        return FakeResult([])

    monkeypatch.setattr(session, "run", run)
    response = client.post("/api/report", headers=AUTH, json={})
    assert response.status_code == 200
    text = response.json()["content"]
    assert "Latest scan import status: partial" in text
    assert "Recorded collection errors: 1" in text
    assert "Skipped TCC grants: 2" in text
    assert "do not establish complete collection coverage" in text
