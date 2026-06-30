from __future__ import annotations

from pathlib import Path
from unittest import TestCase


PIPELINE = Path(__file__).parents[1] / "pipeline.sh"

checks = TestCase()


def _source() -> str:
    return PIPELINE.read_text(encoding="utf-8")


def _line_index(source: str, needle: str) -> int:
    for index, line in enumerate(source.splitlines()):
        if needle in line:
            return index
    raise AssertionError(f"missing pipeline contract fragment: {needle}")


def _line_index_after(source: str, needle: str, start: int) -> int:
    for index, line in enumerate(source.splitlines()[start + 1 :], start + 1):
        if needle in line:
            return index
    raise AssertionError(f"missing pipeline contract fragment after line {start}: {needle}")


def _assert_in_order(source: str, *needles: str) -> None:
    positions = [_line_index(source, needle) for needle in needles]
    checks.assertEqual(positions, sorted(positions), needles)


def _line(source: str, needle: str) -> str:
    return source.splitlines()[_line_index(source, needle)].strip()


def test_pipeline_no_refresh_uses_cached_enrichment_without_fetch() -> None:
    source = _source()

    checks.assertIn('if [[ "$REFRESH_CVE" = true ]]; then', source)
    checks.assertIn(
        'echo "  Using cached CVE enrichment and static registry (--refresh-cve to fetch)"',
        source,
    )
    _assert_in_order(
        source,
        'echo "── Step 2/7: Enriching CVE data ──"',
        'if [[ "$REFRESH_CVE" = true ]]; then',
        'python3 "$SCRIPT_DIR/cve_enrichment.py" --fetch',
        "else",
        "Using cached CVE enrichment",
        'echo "── Step 3/7: Importing scan data ──"',
    )


def test_pipeline_cve_refresh_failure_is_not_suppressed() -> None:
    source = _source()
    refresh_line = _line(source, 'python3 "$SCRIPT_DIR/cve_enrichment.py" --fetch')

    checks.assertIn("set -euo pipefail", source)
    checks.assertEqual(refresh_line, 'python3 "$SCRIPT_DIR/cve_enrichment.py" --fetch')
    _assert_in_order(
        source,
        'python3 "$SCRIPT_DIR/cve_enrichment.py" --fetch',
        'echo "  CVE enrichment refreshed"',
        'echo "── Step 3/7: Importing scan data ──"',
    )


def test_pipeline_requires_password_before_steps() -> None:
    source = _source()
    password_check = _line_index(
        source,
        'if [[ -z "$NEO4J_PASS" && "${NEO4J_AUTH:-}" != "none" ]]; then',
    )
    password_error = _line_index_after(
        source,
        'echo "ERROR: Set NEO4J_PASSWORD or use --password" >&2',
        password_check,
    )
    password_exit = _line_index_after(source, "exit 1", password_error)

    _assert_in_order(
        source,
        'NEO4J_PASS="${NEO4J_PASSWORD:-}"',
        'if [[ -z "$NEO4J_PASS" && "${NEO4J_AUTH:-}" != "none" ]]; then',
        'if [[ -n "$NEO4J_PASS" ]]; then',
        'echo "── Step 1/7: Setting up schema ──"',
    )
    checks.assertLess(password_check, password_error)
    checks.assertLess(password_error, password_exit)
    checks.assertLess(password_exit, _line_index(source, 'if [[ -n "$NEO4J_PASS" ]]; then'))


def test_pipeline_import_failure_stops_before_later_steps() -> None:
    source = _source()
    import_line = _line(source, 'python3 "$SCRIPT_DIR/import_scan.py"')

    checks.assertIn("set -euo pipefail", source)
    checks.assertEqual(
        import_line,
        'python3 "$SCRIPT_DIR/import_scan.py" --input "$SCAN_FILE" "${NEO4J_ARGS[@]}"',
    )
    _assert_in_order(
        source,
        'echo "── Step 3/7: Importing scan data ──"',
        'python3 "$SCRIPT_DIR/import_scan.py" --input "$SCAN_FILE" "${NEO4J_ARGS[@]}"',
        'echo "── Step 4/7: Running inference engine ──"',
    )


def test_pipeline_does_not_pass_password_on_child_argv() -> None:
    source = _source()
    python_invocations = [
        line.strip()
        for line in source.splitlines()
        if line.strip().startswith("python3 ")
    ]

    checks.assertIn('if [[ -n "$NEO4J_PASS" ]]; then', source)
    checks.assertIn('export NEO4J_PASSWORD="$NEO4J_PASS"', source)
    checks.assertIn('NEO4J_ARGS=(--neo4j "$NEO4J_URI" --neo4j-user "$NEO4J_USER")', source)
    checks.assertFalse(any("NEO4J_PASS" in line for line in python_invocations))
    checks.assertFalse(any("--password" in line for line in python_invocations))


def test_pipeline_generates_report_before_full_completion() -> None:
    source = _source()

    checks.assertIn('REPORT_ARGS=("${NEO4J_ARGS[@]}" --output "$REPORT_FILE" --scan-json "$SCAN_FILE")', source)
    _assert_in_order(
        source,
        'echo "── Step 7/7: Generating report ──"',
        'python3 "$SCRIPT_DIR/report.py" "${REPORT_ARGS[@]}"',
        'echo "║          Pipeline complete                       ║"',
    )


def test_pipeline_skip_report_is_explicit_partial_completion() -> None:
    source = _source()

    _assert_in_order(
        source,
        'if [[ "$SKIP_REPORT" = true ]]; then',
        'echo "── Step 7/7: Report generation skipped ──"',
        'echo "║  Pipeline complete without report                ║"',
    )
    checks.assertIn('echo "║          Pipeline complete                       ║"', source)


def test_pipeline_fails_when_default_report_script_is_missing() -> None:
    source = _source()
    report_check = _line_index(source, 'if [[ ! -f "$SCRIPT_DIR/report.py" ]]; then')
    report_error = _line_index_after(
        source,
        'echo "ERROR: report.py not found: $SCRIPT_DIR/report.py" >&2',
        report_check,
    )
    report_exit = _line_index_after(source, "exit 1", report_error)

    _assert_in_order(
        source,
        'if [[ ! -f "$SCRIPT_DIR/report.py" ]]; then',
        'python3 "$SCRIPT_DIR/report.py" "${REPORT_ARGS[@]}"',
    )
    checks.assertLess(report_check, report_error)
    checks.assertLess(report_error, report_exit)
    checks.assertLess(
        report_exit,
        _line_index(source, 'python3 "$SCRIPT_DIR/report.py" "${REPORT_ARGS[@]}"'),
    )


def test_pipeline_fails_when_report_generation_fails() -> None:
    source = _source()
    report_line = _line(source, 'python3 "$SCRIPT_DIR/report.py" "${REPORT_ARGS[@]}"')

    checks.assertIn("set -euo pipefail", source)
    checks.assertEqual(report_line, 'python3 "$SCRIPT_DIR/report.py" "${REPORT_ARGS[@]}"')
    _assert_in_order(
        source,
        'python3 "$SCRIPT_DIR/report.py" "${REPORT_ARGS[@]}"',
        'echo "║          Pipeline complete                       ║"',
    )
