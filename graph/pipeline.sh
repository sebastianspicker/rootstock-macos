#!/usr/bin/env bash
#
# pipeline.sh - One-command Rootstock analysis pipeline.
#
# Runs all steps in order: setup_schema → cve_enrichment → import → infer edges → vulnerabilities → infer score → report
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
#     NEO4J_PASSWORD   required unless NEO4J_AUTH=none
#     NVD_API_KEY      optional; raises the NVD rate limit for --refresh-cve
#
# CVE matching for installed software: --refresh-cve also queries NVD for every
# catalogued third-party app and for the macOS release (by CPE name and installed
# version) and caches the results; the vulnerability import always reads that cache
# for the scan and links matches as AFFECTED_BY evidence.
#
# For interactive visualization after pipeline completes (Canvas-based, pre-computed layout):
#     uv run --project graph --locked rootstock-graph-opengraph-export -o graph.json
#     uv run --project graph --locked rootstock-graph-viewer -i graph.json -o viewer.html
#
# Note: inference runs in two stages. The edge stage creates the inferred relationships
# that the vulnerability importer's category heuristics read; the score stage (tier
# classification, risk scoring, recommendations) reads the imported CVE links.
#
# Exit code 0 on success, non-zero on first failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRAPH_RUN=(uv run --project "$SCRIPT_DIR" --locked)

# ── Parse arguments ─────────────────────────────────────────────────────────

usage() {
    echo "Usage: $0 <scan.json> [--neo4j URI] [--username USER] [--report FILE] [--skip-report] [--refresh-cve] [--keep-previous-scans] [--cve-scan-export FILE] [--serve [PORT]]"
    echo ""
    echo "Runs the full Rootstock pipeline: schema → import → infer edges → vulnerabilities → infer score → report"
    echo ""
    echo "  --refresh-cve   Fetch public CVE enrichment (EPSS, KEV, NVD) before import, including"
    echo "                  NVD CVE matches for installed apps and macOS (default: cached/static only)"
    echo "  --keep-previous-scans"
    echo "                  Keep earlier scans of this Mac (same hostname and hardware UUID; default: replace them)"
    echo "  --replace-host  Accepted for compatibility; replacing is the default"
    echo "  --cve-scan-export FILE"
    echo "                  Import a prebuilt cve-scan rootstock-export.json artifact"
    echo "  --serve [PORT]  Start API server after pipeline (default port: 8000)"
    echo ""
    echo "Environment variables: NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD,"
    echo "  NVD_API_KEY (optional; speeds up NVD matching with --refresh-cve)"
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

# Neo4j connection - non-secret CLI args override env vars.
NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASS="${NEO4J_PASSWORD:-}"
REPORT_FILE=""
SKIP_REPORT=false
REFRESH_CVE=false
KEEP_PREVIOUS=false
CVE_SCAN_EXPORT=""
SERVE=false
SERVE_PORT=8000

while [[ $# -gt 0 ]]; do
    case "$1" in
        --neo4j)     NEO4J_URI="$2"; shift 2 ;;
        --username)  NEO4J_USER="$2"; shift 2 ;;
        --report)    REPORT_FILE="$2"; shift 2 ;;
        --skip-report) SKIP_REPORT=true; shift ;;
        --refresh-cve) REFRESH_CVE=true; shift ;;
        --replace-host) shift ;;
        --keep-previous-scans) KEEP_PREVIOUS=true; shift ;;
        --cve-scan-export) CVE_SCAN_EXPORT="$2"; shift 2 ;;
        --serve)     SERVE=true;
                     if [[ $# -gt 1 && "$2" =~ ^[0-9]+$ ]]; then SERVE_PORT="$2"; shift; fi
                     shift ;;
        -h|--help)   usage ;;
        *)           echo "Unknown option: $1" >&2; usage ;;
    esac
done

if [[ -z "$NEO4J_PASS" && "${NEO4J_AUTH:-}" != "none" ]]; then
    echo "ERROR: Set NEO4J_PASSWORD" >&2
    exit 1
fi

if [[ -n "$CVE_SCAN_EXPORT" && ! -f "$CVE_SCAN_EXPORT" ]]; then
    echo "ERROR: cve-scan export not found: $CVE_SCAN_EXPORT" >&2
    exit 1
fi

if [[ -n "$NEO4J_PASS" ]]; then
    export NEO4J_PASSWORD="$NEO4J_PASS"
fi
NEO4J_ARGS=(--neo4j "$NEO4J_URI" --neo4j-user "$NEO4J_USER")
IMPORT_ARGS=()
if [[ "$KEEP_PREVIOUS" = true ]]; then
    IMPORT_ARGS+=(--keep-previous-scans)
fi

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
"${GRAPH_RUN[@]}" rootstock-graph-setup-schema "${NEO4J_ARGS[@]}"
echo ""

# ── Step 2/7: CVE Enrichment ─────────────────────────────────────────────────

echo "── Step 2/7: Enriching CVE data ──"
if [[ "$REFRESH_CVE" = true ]]; then
    "${GRAPH_RUN[@]}" rootstock-graph-cve-enrichment --fetch --scan-json "$SCAN_FILE"
    echo "  CVE enrichment refreshed"
else
    echo "  Using cached CVE enrichment and static registry (--refresh-cve to fetch)"
fi
echo ""

# ── Step 3/7: Import ─────────────────────────────────────────────────────────

echo "── Step 3/7: Importing scan data ──"
"${GRAPH_RUN[@]}" rootstock-graph-import-scan --input "$SCAN_FILE" "${NEO4J_ARGS[@]}" ${IMPORT_ARGS[@]+"${IMPORT_ARGS[@]}"}
echo ""

# ── Optional: cve-scan artifact import ───────────────────────────────────────

if [[ -n "$CVE_SCAN_EXPORT" ]]; then
    echo "── Optional: Importing cve-scan artifact ──"
    "${GRAPH_RUN[@]}" rootstock-graph-import-cve-scan --input "$CVE_SCAN_EXPORT" "${NEO4J_ARGS[@]}"
    echo ""
fi

# ── Step 4/7: Inference (edges) ──────────────────────────────────────────────

echo "── Step 4/7: Inferring relationships ──"
"${GRAPH_RUN[@]}" rootstock-graph-infer --stage edges "${NEO4J_ARGS[@]}"
echo ""

# ── Step 5/7: Vulnerability import ───────────────────────────────────────────
# Reads inferred relationships for its category heuristics, so it runs after the edge stage.

echo "── Step 5/7: Importing vulnerability data ──"
"${GRAPH_RUN[@]}" rootstock-graph-import-vulnerabilities --scan-json "$SCAN_FILE" "${NEO4J_ARGS[@]}"
echo ""

# ── Step 6/7: Inference (score) ──────────────────────────────────────────────
# Tier classification, risk scoring and recommendations read the CVE links above.

echo "── Step 6/7: Classifying tiers and scoring risk ──"
"${GRAPH_RUN[@]}" rootstock-graph-infer --stage score --allow-empty "${NEO4J_ARGS[@]}"
echo ""

# ── Step 7/7: Report (optional) ──────────────────────────────────────────────

if [[ "$SKIP_REPORT" = true ]]; then
    echo "── Step 7/7: Report generation skipped ──"
else
    echo "── Step 7/7: Generating report ──"
    # Default report output path if not specified
    if [[ -z "$REPORT_FILE" ]]; then
        REPORT_FILE="rootstock-report-$(date +%Y%m%d-%H%M%S).md"
    fi
    REPORT_ARGS=("${NEO4J_ARGS[@]}" --output "$REPORT_FILE" --scan-json "$SCAN_FILE")
    "${GRAPH_RUN[@]}" rootstock-graph-report "${REPORT_ARGS[@]}"
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
if [[ "$SKIP_REPORT" = true ]]; then
    echo "║  Pipeline complete without report                ║"
else
    echo "║          Pipeline complete                       ║"
fi
echo "╚══════════════════════════════════════════════════╝"

# ── Optional: Start API server ────────────────────────────────────────────

if [[ "$SERVE" = true ]]; then
    echo ""
    echo "── Starting API server on port $SERVE_PORT ──"
    "${GRAPH_RUN[@]}" rootstock-graph-api --port "$SERVE_PORT" --neo4j "$NEO4J_URI" --neo4j-user "$NEO4J_USER"
fi
