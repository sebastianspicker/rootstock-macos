#!/usr/bin/env bash
set -euo pipefail

cp "$SRC/rootstock/graph/models.py" "$SRC/models.py"
compile_python_fuzzer "$SRC/fuzz_validate_scan.py"
