"""Guard the Neo4j Browser saved queries against drift from the packaged queries."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from rootstock_graph.cypher import first_cypher_statement
from rootstock_graph.reporting.query_runner import discover_queries


SAVED_QUERIES = Path(__file__).resolve().parents[1] / "browser" / "saved-queries.cypher"
HEADER = re.compile(r"^// ── ★ (?P<title>.+?) ─+$", re.MULTILINE)
ANALYSIS_TITLE = re.compile(r"^ANALYSIS QUERY (?P<number>\d+) - ")

# Browser-only exploration queries have no packaged counterpart by design.
BROWSER_ONLY_TITLES = {
    "EXPLORE 1 - Show All Nodes and Relationships",
    "EXPLORE 2 - Apps with Most TCC Permissions",
    "EXPLORE 3 - Apps with Most Entitlements",
    "EXPLORE 4 - All Inferred Attack Edges",
    "EXPLORE 5 - TCC Grants by Scope (User vs System)",
}


def _normalized(cypher: str) -> str:
    """Compare executable Cypher without layout or comment differences."""
    collapsed = re.sub(r"\s+", " ", first_cypher_statement(cypher))
    return re.sub(r"\s*([^\w\s])\s*", r"\1", collapsed).strip()


def _saved_queries() -> dict[str, str]:
    text = SAVED_QUERIES.read_text(encoding="utf-8")
    headers = list(HEADER.finditer(text))
    return {
        header.group("title"): text[
            header.end() : headers[index + 1].start() if index + 1 < len(headers) else len(text)
        ]
        for index, header in enumerate(headers)
    }


SAVED = _saved_queries()
PACKAGED = {query["id"]: query for query in discover_queries()}


def test_saved_queries_are_packaged_or_declared_browser_only() -> None:
    analysis = {title for title in SAVED if ANALYSIS_TITLE.match(title)}
    assert len(SAVED) == 15
    assert set(SAVED) - analysis == BROWSER_ONLY_TITLES


@pytest.mark.parametrize("title", sorted(title for title in SAVED if ANALYSIS_TITLE.match(title)))
def test_saved_analysis_query_matches_packaged_query(title: str) -> None:
    number = int(ANALYSIS_TITLE.match(title).group("number"))
    packaged = PACKAGED[f"{number:02d}"]
    assert _normalized(SAVED[title]) == _normalized(packaged["cypher"]), packaged["filename"]
