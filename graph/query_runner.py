"""
query_runner.py - Rootstock Interactive Query Runner

CLI:
  python3 query_runner.py --neo4j bolt://... --list
  python3 query_runner.py --neo4j bolt://... --run 01
  python3 query_runner.py --neo4j bolt://... --run all
  python3 query_runner.py --neo4j bolt://... --run 02 --param target_service=kTCCServiceCamera
  python3 query_runner.py --neo4j bolt://... --run 07 --format json
  python3 query_runner.py --neo4j bolt://... --run 16 --format csv

Query metadata is parsed from the comment header in each .cypher file:
  // Name: <name>
  // Purpose: <purpose>
  // Category: <Red Team|Blue Team|Forensic>
  // Severity: <Critical|High|Informational>
  // Parameters: <param list or 'none'>
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path
from typing import Any

from tabulate import tabulate

from utils import first_cypher_statement, list_or_str, run_query

try:
    from neo4j.exceptions import Neo4jError
except ImportError:
    class Neo4jError(Exception):
        pass


# ── Query Discovery ───────────────────────────────────────────────────────────

QUERIES_DIR = Path(__file__).parent / "queries"

_HEADER_RE = re.compile(
    r"^//\s*(?P<key>Name|Purpose|Category|Severity|Parameters|Attack|Use case|CVE|ATT&CK)\s*:\s*(?P<value>.+)$",
    re.IGNORECASE,
)


def _parse_header(cypher: str) -> dict[str, str]:
    """Extract metadata from the comment header of a .cypher file."""
    meta: dict[str, str] = {}
    for line in cypher.splitlines():
        line = line.strip()
        if not line.startswith("//"):
            if line:  # non-empty, non-comment → stop parsing header
                break
            continue  # blank line → skip
        m = _HEADER_RE.match(line)
        if m:
            key = m.group("key").lower().replace(" ", "_")
            meta[key] = m.group("value").strip()
    return meta


def discover_queries() -> list[dict]:
    """
    Scan QUERIES_DIR for all .cypher files and return a sorted list of
    query descriptors (id, filename, metadata, and Cypher body).
    """
    queries: list[dict] = []
    for path in sorted(QUERIES_DIR.glob("*.cypher")):
        if path.parent.name != "queries":
            continue
        stem = path.stem  # e.g., "01-injectable-fda-apps"
        qid = stem.split("-")[0]  # e.g., "01"
        cypher = path.read_text(encoding="utf-8")
        meta = _parse_header(cypher)
        queries.append(
            {
                "id": qid,
                "filename": path.name,
                "path": path,
                "cypher": cypher,
                "name": meta.get("name", stem),
                "purpose": meta.get("purpose", ""),
                "category": meta.get("category", "Unknown"),
                "severity": meta.get("severity", "Unknown"),
                "parameters": meta.get("parameters", "none"),
                "cve": meta.get("cve", ""),
                "mitre_attack": meta.get("att&ck", ""),
            }
        )
    return queries


def find_query(queries: list[dict], query_id: str) -> dict | None:
    """Find a query by its numeric ID prefix (e.g. '01', '1')."""
    normalized = query_id.zfill(2)
    for q in queries:
        if q["id"] == normalized or q["id"] == query_id:
            return q
    return None


# ── Query Execution ───────────────────────────────────────────────────────────


def _coerce_param_value(value: str) -> int | float | str:
    """Convert parameter values to numbers when possible."""
    for converter in (int, float):
        try:
            return converter(value)
        except ValueError:
            continue
    return value


def _parse_params(param_args: list[str]) -> dict[str, Any]:
    """
    Parse --param key=value arguments into a dict suitable for neo4j driver.
    Attempts type coercion: integers and floats are converted automatically.
    """
    params: dict[str, Any] = {}
    for arg in param_args:
        if "=" not in arg:
            print(
                f"Warning: ignoring malformed --param '{arg}' (expected key=value)",
                file=sys.stderr,
            )
            continue
        key, _, value = arg.partition("=")
        params[key] = _coerce_param_value(value)
    return params


# ── Output Formatters ─────────────────────────────────────────────────────────


def format_table(rows: list[dict]) -> str:
    if not rows:
        return "(no results)"
    headers = list(rows[0].keys())
    table_rows = [[list_or_str(row.get(h), "") for h in headers] for row in rows]
    return tabulate(table_rows, headers=headers, tablefmt="simple")


def format_json(rows: list[dict]) -> str:
    # Convert lists to strings for JSON serialisation consistency
    serialisable = [
        {k: (list(v) if isinstance(v, (list, tuple)) else v) for k, v in row.items()}
        for row in rows
    ]
    return json.dumps(serialisable, indent=2, default=str)


def format_csv(rows: list[dict]) -> str:
    if not rows:
        return ""
    buf = io.StringIO()
    headers = list(rows[0].keys())
    writer = csv.DictWriter(buf, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: list_or_str(v, "") for k, v in row.items()})
    return buf.getvalue()


FORMATTERS = {
    "table": format_table,
    "json": format_json,
    "csv": format_csv,
}


def graph_completeness(session) -> tuple[bool, str]:
    """Return whether the latest imported scan is complete enough for positive empty results."""
    try:
        row = _latest_import_metadata_row(session)
    except Neo4jError as exc:
        return False, f"metadata unavailable: {exc}"

    if row is None:
        return False, "no import metadata"

    metadata = dict(row)
    if _import_metadata_is_complete(metadata):
        return True, ""

    return False, ", ".join(_import_metadata_reasons(metadata))


def _latest_import_metadata_row(session):
    return session.run(
        """
        MATCH (c:Computer)
        RETURN c.import_status AS import_status,
               c.collection_error_count AS collection_error_count,
               c.tcc_grants_skipped AS tcc_grants_skipped
        ORDER BY c.scanned_at DESC
        LIMIT 1
        """
    ).single()


def _import_metadata_is_complete(metadata: dict) -> bool:
    return (
        metadata.get("import_status") == "complete"
        and not _collection_error_count(metadata)
        and not _tcc_grants_skipped(metadata)
    )


def _import_metadata_reasons(metadata: dict) -> list[str]:
    reasons = []
    import_status = metadata.get("import_status")
    if import_status != "complete":
        reasons.append(f"import_status={import_status or 'unknown'}")
    collection_error_count = _collection_error_count(metadata)
    if collection_error_count:
        reasons.append(f"collection_errors={collection_error_count}")
    tcc_grants_skipped = _tcc_grants_skipped(metadata)
    if tcc_grants_skipped:
        reasons.append(f"tcc_grants_skipped={tcc_grants_skipped}")
    return reasons


def _collection_error_count(metadata: dict) -> int:
    return metadata.get("collection_error_count") or 0


def _tcc_grants_skipped(metadata: dict) -> int:
    return metadata.get("tcc_grants_skipped") or 0


# ── List Command ──────────────────────────────────────────────────────────────

_CATEGORY_COLOURS = {
    "Red Team": "\033[91m",  # red
    "Blue Team": "\033[94m",  # blue
    "Forensic": "\033[93m",  # yellow
    "Unknown": "\033[0m",
}
_RESET = "\033[0m"

_SEVERITY_COLOURS = {
    "Critical": "\033[91m",
    "High": "\033[93m",
    "Informational": "\033[92m",
    "Unknown": "\033[0m",
}


def cmd_list(queries: list[dict], use_colour: bool = True) -> None:
    """Print a formatted table of all queries."""
    rows = []
    for q in sorted(queries, key=lambda x: x["id"]):
        cat_colour = _CATEGORY_COLOURS.get(q["category"], "") if use_colour else ""
        sev_colour = _SEVERITY_COLOURS.get(q["severity"], "") if use_colour else ""
        reset = _RESET if use_colour else ""
        rows.append(
            [
                q["id"],
                q["name"],
                f"{cat_colour}{q['category']}{reset}",
                f"{sev_colour}{q['severity']}{reset}",
                q["parameters"] if q["parameters"] != "none" else " - ",
            ]
        )

    print(
        tabulate(
            rows,
            headers=["ID", "Name", "Category", "Severity", "Parameters"],
            tablefmt="simple",
        )
    )
    print(f"\n{len(queries)} queries in {QUERIES_DIR}")


# ── Run Command ───────────────────────────────────────────────────────────────


def cmd_run(
    driver,
    queries: list[dict],
    query_id: str,
    params: dict,
    output_format: str,
) -> int:
    """
    Run one or all queries.
    Returns exit code (0 = success, 1 = at least one failure).
    """
    targets = _run_targets(queries, query_id)
    if targets is None:
        return 1

    exit_code = 0
    formatter = FORMATTERS.get(output_format, format_table)

    with driver.session() as session:
        completeness_verified, completeness_reason = graph_completeness(session)
        for q in targets:
            if not _run_one_query(
                session,
                q,
                params,
                formatter,
                completeness_verified,
                completeness_reason,
            ):
                exit_code = 1

    return exit_code


def _run_targets(queries: list[dict], query_id: str) -> list[dict] | None:
    if query_id == "all":
        return sorted(queries, key=lambda x: x["id"])
    query = find_query(queries, query_id)
    if query is None:
        print(f"Error: no query found with ID '{query_id}'", file=sys.stderr)
        print("Use --list to see available query IDs.", file=sys.stderr)
        return None
    return [query]


def _print_query_header(query: dict) -> None:
    print(f"\n{'─' * 60}")
    print(f"[{query['id']}] {query['name']}")
    print(f"    Category: {query['category']}  |  Severity: {query['severity']}")
    if query["purpose"]:
        print(f"    {query['purpose']}")
    if query.get("cve"):
        print(f"    CVE: {query['cve']}")
    if query.get("mitre_attack"):
        print(f"    ATT&CK: {query['mitre_attack']}")
    print(f"{'─' * 60}")


def _print_query_rows(rows: list[dict], formatter) -> None:
    print(formatter(rows))
    row_word = "row" if len(rows) == 1 else "rows"
    print(f"\n    {len(rows)} {row_word} returned.")


def _print_empty_query_result(
    query: dict,
    completeness_verified: bool,
    completeness_reason: str,
) -> None:
    print("    (no results)")
    if query["severity"] not in ("Critical", "High"):
        return
    if completeness_verified:
        print("    ✓ No findings - this is a positive security result.")
    else:
        print(
            "    No rows returned; graph completeness not verified"
            f" ({completeness_reason})."
        )


def _run_one_query(
    session,
    query: dict,
    params: dict,
    formatter,
    completeness_verified: bool,
    completeness_reason: str,
) -> bool:
    _print_query_header(query)
    stmt = first_cypher_statement(query["cypher"])
    try:
        rows = run_query(session, stmt, params)
    except Neo4jError as exc:
        print(f"    ERROR: {exc}", file=sys.stderr)
        return False
    if rows:
        _print_query_rows(rows, formatter)
    else:
        _print_empty_query_result(query, completeness_verified, completeness_reason)
    return True


# ── CLI Entry Point ───────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rootstock Query Runner - execute Cypher queries against a Neo4j graph",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # List all available queries
  python3 query_runner.py --list

  # Run query 01 (default: table output)
  python3 query_runner.py --run 01

  # Run with a parameter
  python3 query_runner.py --run 11 --param target_service=kTCCServiceCamera

  # Output as JSON
  python3 query_runner.py --run 21 --format json

  # Output as CSV and pipe to file
  python3 query_runner.py --run 16 --format csv > tcc-audit.csv

  # Run all queries sequentially
  python3 query_runner.py --run all
""",
    )

    from neo4j_connection import add_neo4j_args

    add_neo4j_args(parser)
    parser.add_argument(
        "--list", action="store_true", help="List all queries with metadata"
    )
    parser.add_argument("--run", metavar="ID|all", help="Run a query by ID or 'all'")
    parser.add_argument(
        "--param",
        metavar="key=value",
        action="append",
        default=[],
        help="Query parameter (repeatable, e.g. --param min_permissions=5)",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colour output"
    )
    return parser


def _run_cli_command(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if not args.list and not args.run:
        parser.print_help()
        return 0

    queries = discover_queries()
    if not queries:
        print(f"No .cypher files found in {QUERIES_DIR}", file=sys.stderr)
        return 1

    if args.list:
        cmd_list(queries, use_colour=not args.no_color)
        if not args.run:
            return 0

    if args.run:
        from neo4j_connection import connect_from_args

        driver = connect_from_args(args)

        params = _parse_params(args.param)
        exit_code = cmd_run(driver, queries, args.run, params, args.format)
        driver.close()
        return exit_code
    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    return _run_cli_command(args, parser)


if __name__ == "__main__":
    sys.exit(main())
