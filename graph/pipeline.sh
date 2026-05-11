#!/usr/bin/env bash
#
# pipeline.sh — One-command Rootstock analysis pipeline.
#
# Runs all steps in order: setup_schema → cve_enrichment → import → infer → vulnerabilities → classify → report
#
# Usage:
#     ./graph/pipeline.sh scan.json
#     ./graph/pipeline.sh scan.json --neo4j bolt://localhost:7687 --report output.md
#     ./graph/pipeline.sh scan.json --cve-scan-export rootstock-export.json
#     ./graph/pipeline.sh scan.json --skip-report
#
# Environment variables (override defaults):
#     NEO4J_URI       bolt://localhost:7687
#     NEO4J_USER      neo4j
#     NEO4J_PASSWORD   (required — no default)
#
# For interactive visualization after pipeline completes (Canvas-based, pre-computed layout):
#     python3 graph/opengraph_export.py -o graph.json && python3 graph/viewer.py -i graph.json -o viewer.html
#
# Note: infer.py internally runs risk scoring (infer_risk_score) and recommendation
# generation (infer_recommendations) as part of its inference engine pipeline.
#
# Exit code 0 on success, non-zero on first failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Parse arguments ─────────────────────────────────────────────────────────

usage() {
    echo "Usage: $0 <scan.json> [--neo4j URI] [--username USER] [--password PASS] [--report FILE] [--skip-report] [--refresh-cve] [--cve-scan-export FILE] [--serve [PORT]]"
    echo ""
    echo "Runs the full Rootstock pipeline: schema → import → infer → classify → report"
    echo ""
    echo "  --refresh-cve   Fetch public CVE enrichment before import (default: cached/static only)"
    echo "  --cve-scan-export FILE"
    echo "                  Import a prebuilt cve-scan rootstock-export.json artifact"
    echo "  --serve [PORT]  Start API server after pipeline (default port: 8000)"
    echo ""
    echo "Environment variables: NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD"
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

SCAN_FILE="$1"
shift

if [[ ! -f "$SCAN_FILE" ]]; then
    echo "ERROR: Scan file not found: $SCAN_FILE" >&2
    exit 1
fi

# Neo4j connection — CLI args override env vars, env vars override defaults
NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASS="${NEO4J_PASSWORD:-}"
REPORT_FILE=""
SKIP_REPORT=false
REFRESH_CVE=false
CVE_SCAN_EXPORT=""
SERVE=false
SERVE_PORT=8000

while [[ $# -gt 0 ]]; do
    case "$1" in
        --neo4j)     NEO4J_URI="$2"; shift 2 ;;
        --username)  NEO4J_USER="$2"; shift 2 ;;
        --password)  NEO4J_PASS="$2"; shift 2 ;;
        --report)    REPORT_FILE="$2"; shift 2 ;;
        --skip-report) SKIP_REPORT=true; shift ;;
        --refresh-cve) REFRESH_CVE=true; shift ;;
        --cve-scan-export) CVE_SCAN_EXPORT="$2"; shift 2 ;;
        --serve)     SERVE=true;
                     if [[ $# -gt 1 && "$2" =~ ^[0-9]+$ ]]; then SERVE_PORT="$2"; shift; fi
                     shift ;;
        -h|--help)   usage ;;
        *)           echo "Unknown option: $1" >&2; usage ;;
    esac
done

if [[ -z "$NEO4J_PASS" ]]; then
    echo "ERROR: Set NEO4J_PASSWORD or use --password" >&2
    exit 1
fi

if [[ -n "$CVE_SCAN_EXPORT" && ! -f "$CVE_SCAN_EXPORT" ]]; then
    echo "ERROR: cve-scan export not found: $CVE_SCAN_EXPORT" >&2
    exit 1
fi

export NEO4J_PASSWORD="$NEO4J_PASS"
NEO4J_ARGS=(--neo4j "$NEO4J_URI" --neo4j-user "$NEO4J_USER")

echo "╔══════════════════════════════════════════════════╗"
echo "║         Rootstock Analysis Pipeline              ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Scan:     $SCAN_FILE"
echo "Neo4j:    $NEO4J_URI"
if [[ -n "$CVE_SCAN_EXPORT" ]]; then
    echo "cve-scan: $CVE_SCAN_EXPORT"
fi
echo ""

# ── Step 1/7: Schema ─────────────────────────────────────────────────────────

echo "── Step 1/7: Setting up schema ──"
python3 "$SCRIPT_DIR/setup_schema.py" "${NEO4J_ARGS[@]}"
echo ""

# ── Step 2/7: CVE Enrichment (offline-safe) ──────────────────────────────────

echo "── Step 2/7: Enriching CVE data ──"
if [[ "$REFRESH_CVE" = true ]]; then
    python3 "$SCRIPT_DIR/cve_enrichment.py" --fetch || echo "  ⚠ CVE enrichment skipped (offline?)"
else
    echo "  Using cached CVE enrichment and static registry (--refresh-cve to fetch)"
fi
echo ""

# ── Step 3/7: Import ─────────────────────────────────────────────────────────

echo "── Step 3/7: Importing scan data ──"
python3 "$SCRIPT_DIR/import.py" --input "$SCAN_FILE" "${NEO4J_ARGS[@]}"
echo ""

# ── Optional: cve-scan artifact import ───────────────────────────────────────

if [[ -n "$CVE_SCAN_EXPORT" ]]; then
    echo "── Optional: Importing cve-scan artifact ──"
    python3 "$SCRIPT_DIR/import_cve_scan.py" --input "$CVE_SCAN_EXPORT" "${NEO4J_ARGS[@]}"
    echo ""
fi

# ── Step 4/7: Inference ──────────────────────────────────────────────────────
# Note: infer.py runs all inference modules including risk scoring and recommendations

echo "── Step 4/7: Running inference engine ──"
python3 "$SCRIPT_DIR/infer.py" "${NEO4J_ARGS[@]}"
echo ""

# ── Step 5/7: Vulnerability import ───────────────────────────────────────────

echo "── Step 5/7: Importing vulnerability data ──"
python3 "$SCRIPT_DIR/import_vulnerabilities.py" "${NEO4J_ARGS[@]}"
echo ""

# ── Step 6/7: Tier classification ────────────────────────────────────────────

echo "── Step 6/7: Classifying tiers ──"
python3 "$SCRIPT_DIR/tier_classification.py" "${NEO4J_ARGS[@]}"
echo ""

# ── Step 7/7: Report (optional) ──────────────────────────────────────────────

if [[ "$SKIP_REPORT" = true ]]; then
    echo "── Step 7/7: Report generation skipped ──"
else
    echo "── Step 7/7: Generating report ──"
    if [[ -f "$SCRIPT_DIR/report.py" ]]; then
        # Default report output path if not specified
        if [[ -z "$REPORT_FILE" ]]; then
            REPORT_FILE="rootstock-report-$(date +%Y%m%d-%H%M%S).md"
        fi
        REPORT_ARGS=("${NEO4J_ARGS[@]}" --output "$REPORT_FILE" --scan-json "$SCAN_FILE")
        python3 "$SCRIPT_DIR/report.py" "${REPORT_ARGS[@]}"
    else
        echo "  report.py not found — skipping report generation"
    fi
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║          Pipeline complete                       ║"
echo "╚══════════════════════════════════════════════════╝"

# ── Optional: Start API server ────────────────────────────────────────────

if [[ "$SERVE" = true ]]; then
    echo ""
    echo "── Starting API server on port $SERVE_PORT ──"
    python3 "$SCRIPT_DIR/server.py" --port "$SERVE_PORT" --neo4j "$NEO4J_URI" --neo4j-user "$NEO4J_USER"
fi
