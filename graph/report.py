"""
report.py — Rootstock Security Assessment Report Generator.

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

from neo4j_connection import add_neo4j_args, connect_from_args
from query_runner import discover_queries, load_cypher
from utils import first_cypher_statement, run_query
from report_formatters import (  # noqa: F401
    format_no_findings,
    format_generic_table,
    format_injectable_fda_table,
    format_electron_table,
    format_apple_event_table,
    format_tcc_overview_table,
    format_private_entitlement_table,
    format_executive_summary,
)
from report_assembly import (  # noqa: F401
    RECOMMENDATIONS,
    assemble_report,
    markdown_to_html,
)


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
            filename = q["filename"]
            try:
                cypher = load_cypher(q)
                stmt = first_cypher_statement(cypher)
                params = _DEFAULT_PARAMS if _has_parameters(q) else {}
                rows = run_query(session, stmt, params)
                results[filename] = rows
                print(f"  ✓ {filename}: {len(rows)} rows", file=sys.stderr)
            except Exception as e:
                results[filename] = f"Query failed: {e}"
                print(f"  ✗ {filename}: {e}", file=sys.stderr)

    return results


# ── Scan Metadata ─────────────────────────────────────────────────────────────


def get_scan_metadata_from_neo4j(driver) -> dict:
    """Query Neo4j for node counts and available scan metadata."""
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
        except Exception as e:
            print(f"  ⚠ Metadata query failed: {e}", file=sys.stderr)
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
        except Exception as e:
            print(f"  ⚠ Scan metadata query failed: {e}", file=sys.stderr)
            meta_row = {}

    return {**row, **meta_row}


def get_scan_metadata_from_json(json_path: Path) -> dict:
    """Read scan metadata from the original collector JSON file."""
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        elev = data.get("elevation", {})
        return {
            "scan_id": data.get("scan_id", "unknown"),
            "hostname": data.get("hostname", socket.gethostname()),
            "macos_version": data.get("macos_version", "unknown"),
            "collector_version": data.get("collector_version", "unknown"),
            "timestamp": data.get("timestamp", "unknown"),
            "is_root": elev.get("is_root", False),
            "has_fda": elev.get("has_fda", False),
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
    except Exception as e:
        return {"error": str(e)}


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> int:
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
    args = parser.parse_args()

    # Connect to Neo4j
    driver = connect_from_args(args)

    # Gather metadata
    if args.scan_json:
        metadata = get_scan_metadata_from_json(Path(args.scan_json))
    else:
        metadata = get_scan_metadata_from_neo4j(driver)

    # Run queries
    print("Running queries…", file=sys.stderr)
    query_results = run_all_queries(driver)
    driver.close()

    # Assemble report
    print("Assembling report…", file=sys.stderr)
    md = assemble_report(query_results, metadata)

    # Write output
    out_path = Path(args.output)
    if args.format == "html":
        content = markdown_to_html(md)
    else:
        content = md

    out_path.write_text(content, encoding="utf-8")
    print(f"Report written to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
