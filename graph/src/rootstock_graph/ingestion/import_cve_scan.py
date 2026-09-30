#!/usr/bin/env python3
"""
rootstock-graph-import-cve-scan - Import a cve-scan Rootstock export into Neo4j.

The importer consumes the artifact produced by:

    cve-scan export-rootstock <run-dir>

It imports only the prebuilt JSON artifact. It does not call cve-scan internals
and does not require Neo4j during scanning.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..neo4j import add_neo4j_args, connect_from_args
from .cve_scan_contract import CveScanImportError, load_export
from .cve_scan_neo4j import import_cve_scan_export


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import a cve-scan rootstock-export.json artifact into Neo4j"
    )
    parser.add_argument("--input", required=True, help="Path to rootstock-export.json")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate the artifact without opening a Neo4j connection",
    )
    add_neo4j_args(parser)
    args = parser.parse_args()

    try:
        export = load_export(Path(args.input))
    except CveScanImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.validate_only:
        print(
            "Validated cve-scan export "
            f"({len(export.nodes)} nodes, {len(export.edges)} relationships)"
        )
        return 0

    driver = connect_from_args(args)
    with driver.session() as session:
        counts = import_cve_scan_export(session, export)
    driver.close()

    print(
        "Imported cve-scan export "
        f"({counts['nodes']} nodes, {counts['edges']} relationships, "
        f"{counts['affected_by_aliases']} AFFECTED_BY aliases)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
