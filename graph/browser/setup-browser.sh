#!/usr/bin/env bash
# setup-browser.sh — Rootstock Neo4j Browser Integration Setup
#
# This script:
#   1. Serves the Browser Guide and GraSS file over HTTP
#   2. Prints step-by-step instructions for Neo4j Browser setup
#
# Usage:
#   cd graph/browser
#   chmod +x setup-browser.sh
#   ./setup-browser.sh
#
# Requirements:
#   - Python 3 (for HTTP server)
#   - Neo4j running (Docker or native)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HTTP_PORT="${ROOTSTOCK_HTTP_PORT:-8001}"
NEO4J_BOLT="${NEO4J_BOLT:-bolt://localhost:7687}"

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

header() { echo -e "\n${BLUE}══════════════════════════════════════════════════${NC}"; }
step()   { echo -e "${GREEN}[STEP]${NC} $*"; }
info()   { echo -e "${CYAN}[INFO]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }

header
echo -e "${BLUE}  Rootstock — Neo4j Browser Setup${NC}"
header

# ── Check dependencies ────────────────────────────────────────────────────────
info "Checking dependencies…"

if ! command -v python3 &>/dev/null; then
    warn "python3 not found — cannot start HTTP server."
    warn "Install Python 3 or manually copy files to Neo4j's import directory."
    exit 1
fi

# ── Verify files exist ────────────────────────────────────────────────────────
for f in rootstock-guide.html rootstock-style.grass saved-queries.cypher; do
    if [[ ! -f "$SCRIPT_DIR/$f" ]]; then
        warn "Missing file: $SCRIPT_DIR/$f"
        exit 1
    fi
done
info "All browser files present."

# ── Optional: Copy to Docker Neo4j import volume ──────────────────────────────
DOCKER_CONTAINER="${NEO4J_CONTAINER:-rootstock-neo4j}"

if command -v docker &>/dev/null && docker inspect "$DOCKER_CONTAINER" &>/dev/null 2>&1; then
    step "Detected Docker container: $DOCKER_CONTAINER"
    info "Copying files to Neo4j import directory inside container…"

    docker exec "$DOCKER_CONTAINER" mkdir -p /import/rootstock 2>/dev/null || true
    docker cp "$SCRIPT_DIR/rootstock-guide.html" "$DOCKER_CONTAINER:/import/rootstock/"
    docker cp "$SCRIPT_DIR/rootstock-style.grass" "$DOCKER_CONTAINER:/import/rootstock/"
    docker cp "$SCRIPT_DIR/saved-queries.cypher"  "$DOCKER_CONTAINER:/import/rootstock/"

    info "Files copied to container."
    info "To serve from container: docker exec -it $DOCKER_CONTAINER python3 -m http.server 8001 --directory /import/rootstock"
    echo ""
fi

# ── Start HTTP server ─────────────────────────────────────────────────────────
step "Starting HTTP server on port $HTTP_PORT…"
info "Serving: $SCRIPT_DIR"
info "Press Ctrl+C to stop the server."
echo ""

header
echo ""
echo -e "  ${BLUE}Neo4j Browser Setup Instructions${NC}"
echo ""
step "1. Open Neo4j Browser at http://localhost:7474"
echo ""
step "2. Load the Rootstock style sheet:"
echo -e "   ${CYAN}:style http://localhost:$HTTP_PORT/rootstock-style.grass${NC}"
echo ""
step "3. Load the interactive guide:"
echo -e "   ${CYAN}:play http://localhost:$HTTP_PORT/rootstock-guide.html${NC}"
echo ""
step "4. Navigate the guide slides with the ← → arrows in the guide panel."
echo ""
step "5. Click any Cypher block in the guide to run it directly."
echo ""
info "Saved queries are in: graph/browser/saved-queries.cypher"
info "Paste any query into the Neo4j Browser editor and click the star (☆) to save it."
echo ""
header

# ── Kill existing python3 http.server on same port (avoid bind error) ────────
lsof -ti tcp:"$HTTP_PORT" 2>/dev/null | while read -r pid; do
    if ps -p "$pid" -o args= 2>/dev/null | grep -q "python3 -m http.server"; then
        kill "$pid" 2>/dev/null || true
    fi
done

cd "$SCRIPT_DIR"
exec python3 -m http.server "$HTTP_PORT"
