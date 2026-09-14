"""Generate bounded, read-only assessment downloads without filesystem access."""

from __future__ import annotations

import time
from typing import Literal

from fastapi import HTTPException
from neo4j import Query
from neo4j.exceptions import DriverError, Neo4jError
from pydantic import BaseModel, ConfigDict

from ..reporting.query_runner import discover_queries
from ..reporting.report import _DEFAULT_PARAMS, get_scan_metadata_from_session
from ..reporting.report_assembly import assemble_report, markdown_to_html
from ..server_validation import validate_api_cypher
from ..utils import first_cypher_statement, run_query

MAX_QUERY_ROWS = 1_000
MAX_TOTAL_ROWS = 20_000
MAX_REPORT_BYTES = 8 * 1024 * 1024
REPORT_TIMEOUT_SECONDS = 12.0


class ReportRequest(BaseModel):
    """Only the format is client-controlled; no server paths or query text."""

    model_config = ConfigDict(extra="forbid")
    format: Literal["markdown", "html"] = "markdown"


class _TimedSession:
    """Apply the remaining request budget to every report and metadata query."""

    def __init__(self, session):
        self.session = session
        self.deadline = time.monotonic() + REPORT_TIMEOUT_SECONDS

    def check_budget(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise HTTPException(504, "Report generation exceeded the interactive time limit")
        return min(5.0, remaining)

    def run(self, statement, *args, **kwargs):
        return self.session.run(Query(str(statement), timeout=self.check_budget()), *args, **kwargs)


def _query_results(session: _TimedSession) -> dict[str, list[dict]]:
    results: dict[str, list[dict]] = {}
    total_rows = 0
    for query in discover_queries():
        statement = first_cypher_statement(query["cypher"])
        if validate_api_cypher(statement):
            raise HTTPException(500, "A configured report query is not read-only")
        rows = run_query(session, statement, _DEFAULT_PARAMS, maximum_rows=MAX_QUERY_ROWS + 1)
        total_rows += len(rows)
        if len(rows) > MAX_QUERY_ROWS or total_rows > MAX_TOTAL_ROWS:
            raise HTTPException(
                413,
                "Report exceeds interactive result limits. Use the local report CLI for this graph.",
            )
        results[query["filename"]] = rows
    return results


def _coverage_note(session: _TimedSession, metadata: dict) -> str:
    row = (
        session.run("""
        MATCH (c:Computer)
        RETURN count(c) AS scans,
               count(c.collection_error_count) AS known,
               sum(c.collection_error_count) AS errors,
               sum(c.tcc_grants_skipped) AS skipped
    """).single()
        or {}
    )
    scans = row.get("scans", 0)
    if not scans or row.get("known", 0) != scans:
        coverage = "Collection coverage is unavailable for some or all loaded scans."
    else:
        coverage = (
            f"Loaded scans: {scans}. Recorded collection errors: {row.get('errors', 0)}. "
            f"Skipped TCC grants: {row.get('skipped', 0)}. "
            "These counts do not establish complete collection coverage."
        )
    status = metadata.get("import_status")
    status = status if status in {"complete", "partial"} else "unknown"
    return (
        "> This assessment covers the current loaded graph, not only the selected application. "
        "Scan metadata below describes the most recent imported host scan. "
        f"Latest scan import status: {status}. {coverage} "
        "Modeled relationships are not confirmation of compromise.\n\n"
    )


def generate_report(session, request: ReportRequest) -> dict[str, str]:
    """Reuse report assembly; fail closed on query failure, truncation or timeout."""
    timed = _TimedSession(session)
    try:
        metadata = get_scan_metadata_from_session(timed)
        if metadata.get("_metadata_errors"):
            raise HTTPException(503, "Report metadata could not be read")
        for field in ("hostname", "timestamp"):
            if not metadata.get(field):
                metadata[field] = "Unknown"
        note = _coverage_note(timed, metadata)
        rows = _query_results(timed)
        timed.check_budget()
        markdown = note + assemble_report(rows, metadata)
        content = markdown_to_html(markdown) if request.format == "html" else markdown
        timed.check_budget()
        if len(content.encode("utf-8")) > MAX_REPORT_BYTES:
            raise HTTPException(413, "Report exceeds the interactive download size limit")
    except (DriverError, Neo4jError, ValueError, TypeError) as error:
        raise HTTPException(
            503, "Report generation failed; no complete report was produced"
        ) from error
    extension = "html" if request.format == "html" else "md"
    return {
        "content": content,
        "filename": f"rootstock-assessment.{extension}",
        "media_type": "text/html" if request.format == "html" else "text/markdown",
    }
