#!/usr/bin/env bash
# test_benchmark.sh - benchmark.sh failure handling smoke tests.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"

cleanup() {
	rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TMP_DIR/scripts" "$TMP_DIR/docs/private"
cp "$REPO_ROOT/scripts/benchmark.sh" "$TMP_DIR/scripts/benchmark.sh"
chmod +x "$TMP_DIR/scripts/benchmark.sh"

FAKE_TIME="$TMP_DIR/fake-time"
{
	printf '%s\n' '#!/usr/bin/env bash'
	printf '%s\n' 'set +e'
	printf '%s\n' '"$@"'
	printf '%s\n' 'STATUS=$?'
	printf '%s\n' '{'
	printf '%s\n' '	echo "0.01 real"'
	printf '%s\n' '	echo "0.01 user"'
	printf '%s\n' '	echo "0.00 sys"'
	printf '%s\n' '	echo "1048576 maximum resident"'
	printf '%s\n' '} >&2'
	printf '%s\n' "exit \"\$STATUS\""
} >"$FAKE_TIME"
chmod +x "$FAKE_TIME"

python3 -c 'from pathlib import Path; import sys; script = Path(sys.argv[1]); fake_time = sys.argv[2]; script.write_text(script.read_text(encoding="utf-8").replace("/usr/bin/time -l", f"\"{fake_time}\""), encoding="utf-8")' "$TMP_DIR/scripts/benchmark.sh" "$FAKE_TIME"

FAKE_COLLECTOR="$TMP_DIR/fake-collector"
{
	printf '%s\n' '#!/usr/bin/env python3'
	printf '%s\n' 'import os'
	printf '%s\n' 'import sys'
	printf '%s\n' ''
	printf '%s\n' ''
	printf '%s\n' 'def option_value(args, name):'
	printf '%s\n' '    try:'
	printf '%s\n' '        return args[args.index(name) + 1]'
	printf '%s\n' '    except (ValueError, IndexError):'
	printf '%s\n' '        return ""'
	printf '%s\n' ''
	printf '%s\n' ''
	printf '%s\n' 'output = option_value(sys.argv, "--output")'
	printf '%s\n' 'verbose = "--verbose" in sys.argv'
	printf '%s\n' 'mode = os.environ.get("FAKE_MODE", "success")'
	printf '%s\n' ''
	printf '%s\n' 'if mode == "fail":'
	printf '%s\n' '    sys.exit(42)'
	printf '%s\n' 'if mode == "malformed":'
	printf '%s\n' '    with open(output, "w", encoding="utf-8") as outfile:'
	printf '%s\n' '        outfile.write("{not json\n")'
	printf '%s\n' '    sys.exit(0)'
	printf '%s\n' 'if mode != "success":'
	printf '%s\n' '    print("unknown FAKE_MODE", file=sys.stderr)'
	printf '%s\n' '    sys.exit(64)'
	printf '%s\n' ''
	printf '%s\n' 'with open(output, "w", encoding="utf-8") as outfile:'
	printf '%s\n' '    outfile.write('\''{"applications":[{},{}],"tcc_grants":[{}]}\n'\'')'
	printf '%s\n' 'if verbose:'
	printf '%s\n' '    print("  [Fixture] 0.01s")'
	printf '%s\n' '    print("Total: 0.01s")'
} >"$FAKE_COLLECTOR"
chmod +x "$FAKE_COLLECTOR"

BASELINE="$TMP_DIR/docs/private/benchmark-results.md"

if FAKE_MODE=fail "$TMP_DIR/scripts/benchmark.sh" "$FAKE_COLLECTOR" >"$TMP_DIR/fail.out" 2>"$TMP_DIR/fail.err"; then
	echo "expected nonzero collector run to fail benchmark" >&2
	exit 1
fi
if [[ -f "$BASELINE" ]]; then
	echo "baseline should not be written after failed collector run" >&2
	exit 1
fi
grep -q "collector run 1 failed with exit status" "$TMP_DIR/fail.err"

if FAKE_MODE=malformed "$TMP_DIR/scripts/benchmark.sh" "$FAKE_COLLECTOR" >"$TMP_DIR/malformed.out" 2>"$TMP_DIR/malformed.err"; then
	echo "expected malformed collector JSON to fail benchmark" >&2
	exit 1
fi
if [[ -f "$BASELINE" ]]; then
	echo "baseline should not be written after malformed collector JSON" >&2
	exit 1
fi
grep -q "collector run 1 produced invalid JSON" "$TMP_DIR/malformed.err"

FAKE_MODE=success "$TMP_DIR/scripts/benchmark.sh" "$FAKE_COLLECTOR" >"$TMP_DIR/success.out" 2>"$TMP_DIR/success.err"
grep -q "Results appended to" "$TMP_DIR/success.out"
grep -q "| Apps scanned     | 2 | 2 | 2 |" "$BASELINE"
grep -q "| TCC grants       | 1 | 1 | 1 |" "$BASELINE"
