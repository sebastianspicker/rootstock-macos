"""
report.py - Rootstock Security Assessment Report Generator.

CLI: python3 report.py --neo4j bolt://localhost:7687 --output report.md
     python3 report.py --neo4j bolt://localhost:7687 --output report.html --format html
     python3 report.py --neo4j bolt://localhost:7687 --output report.md --scan-json scan.json

Architecture:
  1. Connect to Neo4j, run all queries from graph/queries/*.cypher
  2. Format each result set into a Markdown section with tabulate
  3. Generate Mermaid diagrams for critical findings
  4. Assemble full report document and write to output file

Implementation split across modules:
  - report_formatters.py: table and section formatters
  - report_assembly.py: report assembly, recommendations, HTML conversion
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

from neo4j.exceptions import DriverError, Neo4jError

from neo4j_connection import add_neo4j_args, connect_from_args
from query_runner import discover_queries
from utils import first_cypher_statement, run_query
from report_assembly import assemble_report, markdown_to_html


class ScanMetadataError(RuntimeError):
    """Raised when report metadata cannot be read from scan JSON."""


# ── Default Parameters for Parameterized Queries ────────────────────────────

_DEFAULT_PARAMS = {
    "target_service": "kTCCServiceSystemPolicyAllFiles",
    "min_permissions": 3,
    "team_id": "",
    "bundle_id": "",
    "days_old": 365,
    "min_methods": 1,
    "username": "",
    "scope": None,
    "app_name": None,
}


# ── Query Execution ───────────────────────────────────────────────────────────


def _has_parameters(query: dict) -> bool:
    """Check if a query descriptor declares parameters."""
    return query.get("parameters", "none").lower() != "none"


def run_all_queries(driver) -> dict[str, list[dict] | str]:
    """
    Run all discovered queries, returning results keyed by filename.
    On failure, stores an error string instead of a list.
    """
    queries = discover_queries()
    results: dict[str, list[dict] | str] = {}

    with driver.session() as session:
        for q in queries:
            filename, result = _run_report_query(session, q)
            results[filename] = result

    return results


def _run_report_query(session, query: dict) -> tuple[str, list[dict] | str]:
    filename = query["filename"]
    try:
        statement = first_cypher_statement(query["cypher"])
        params = _DEFAULT_PARAMS if _has_parameters(query) else {}
        rows = run_query(session, statement, params)
        print(f"  ✓ {filename}: {len(rows)} rows", file=sys.stderr)
        return filename, rows
    except (DriverError, Neo4jError, TypeError, ValueError) as error:
        print(f"  ✗ {filename}: {error}", file=sys.stderr)
        return filename, f"Query failed: {error}"


# ── Scan Metadata ─────────────────────────────────────────────────────────────


def get_scan_metadata_from_neo4j(driver) -> dict:
    """Query Neo4j for node counts and available scan metadata."""
    errors = []
    with driver.session() as session:
        try:
            row = dict(
                session.run("""
                MATCH (a:Application)
                WITH count(a) AS app_count
                OPTIONAL MATCH (g:Application)-[:HAS_TCC_GRANT]->(p:TCC_Permission)
                WITH app_count, count(g) AS tcc_grant_count
                OPTIONAL MATCH (e:Application)-[:HAS_ENTITLEMENT]->(en:Entitlement)
                RETURN app_count, tcc_grant_count, count(en) AS entitlement_count
            """).single()
                or {}
            )
        except (DriverError, Neo4jError) as e:
            print(f"  ⚠ Metadata query failed: {e}", file=sys.stderr)
            errors.append(f"metadata counts: {e}")
            row = {}

        try:
            meta_row = dict(
                session.run("""
                MATCH (c:Computer)
                RETURN c.scan_id AS scan_id,
                       c.hostname AS hostname,
                       c.macos_version AS macos_version,
                       c.collector_version AS collector_version,
                       c.scanned_at AS timestamp,
                       c.elevation_is_root AS is_root,
                       c.elevation_has_fda AS has_fda,
                       c.icloud_signed_in AS icloud_signed_in,
                       c.icloud_drive_enabled AS icloud_drive_enabled,
                       c.icloud_keychain_enabled AS icloud_keychain_enabled
                ORDER BY c.scanned_at DESC
                LIMIT 1
            """).single()
                or {}
            )
        except (DriverError, Neo4jError) as e:
            print(f"  ⚠ Scan metadata query failed: {e}", file=sys.stderr)
            errors.append(f"scan metadata: {e}")
            meta_row = {}

    metadata = {**row, **meta_row}
    if errors:
        metadata["_metadata_errors"] = errors
    return metadata


def get_scan_metadata_from_json(json_path: Path) -> dict:
    """Read scan metadata from the original collector JSON file."""
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        elev = data.get("elevation") if isinstance(data.get("elevation"), dict) else {}
        return {
            "scan_id": data.get("scan_id", "unknown"),
            "hostname": data.get("hostname", socket.gethostname()),
            "macos_version": data.get("macos_version", "unknown"),
            "collector_version": data.get("collector_version", "unknown"),
            "timestamp": data.get("timestamp", "unknown"),
            "is_root": elev.get("is_root"),
            "has_fda": elev.get("has_fda"),
            "app_count": len(data.get("applications", [])),
            "tcc_grant_count": len(data.get("tcc_grants", [])),
            "entitlement_count": sum(
                len(a.get("entitlements", [])) for a in data.get("applications", [])
            ),
            "bluetooth_device_count": len(data.get("bluetooth_devices", [])),
            "file_acl_count": len(data.get("file_acls", [])),
            "login_session_count": len(data.get("login_sessions", [])),
            "icloud_signed_in": data.get("icloud_signed_in"),
            "icloud_drive_enabled": data.get("icloud_drive_enabled"),
            "icloud_keychain_enabled": data.get("icloud_keychain_enabled"),
        }
    except (AttributeError, json.JSONDecodeError, OSError, TypeError) as e:
        raise ScanMetadataError(
            f"Cannot read scan metadata from {json_path}: {e}"
        ) from e


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = _parser()
    args = parser.parse_args()

    driver = connect_from_args(args)

    metadata = _report_metadata(args, driver)
    if isinstance(metadata, ScanMetadataError):
        driver.close()
        print(f"Report metadata failed: {metadata}", file=sys.stderr)
        return 1

    print("Running queries…", file=sys.stderr)
    query_results = run_all_queries(driver)
    driver.close()

    if _report_query_failures(query_results):
        return 1

    print("Assembling report…", file=sys.stderr)
    md = assemble_report(query_results, metadata)
    _write_report(args, md)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rootstock Security Assessment Report Generator"
    )
    add_neo4j_args(parser)
    parser.add_argument("--output", required=True, help="Output report file path")
    parser.add_argument(
        "--format",
        choices=["markdown", "html"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--scan-json",
        help="Optional: path to original scan.json for richer metadata",
    )
    return parser


def _report_metadata(args: argparse.Namespace, driver) -> dict | ScanMetadataError:
    if args.scan_json:
        return _metadata_from_scan_json(Path(args.scan_json))

    return _checked_neo4j_metadata(driver)


def _metadata_from_scan_json(path: Path) -> dict | ScanMetadataError:
    try:
        return get_scan_metadata_from_json(path)
    except ScanMetadataError as error:
        return error


def _checked_neo4j_metadata(driver) -> dict | ScanMetadataError:
    metadata = get_scan_metadata_from_neo4j(driver)
    if metadata.get("_metadata_errors"):
        return ScanMetadataError(str(metadata.get("_metadata_errors")))
    return metadata


def _report_query_failures(query_results: dict[str, list[dict] | str]) -> bool:
    failures = {
        filename: result
        for filename, result in query_results.items()
        if isinstance(result, str)
    }
    if not failures:
        return False

    print("Report query failures:", file=sys.stderr)
    for filename, error in sorted(failures.items()):
        print(f"  {filename}: {error}", file=sys.stderr)
    return True


def _write_report(args: argparse.Namespace, markdown: str) -> None:
    out_path = Path(args.output)
    content = markdown_to_html(markdown) if args.format == "html" else markdown
    out_path.write_text(content, encoding="utf-8")
    print(f"Report written to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
