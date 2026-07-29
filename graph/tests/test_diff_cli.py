from __future__ import annotations

from pathlib import Path

from diff_scans import main


def test_diff_cli_reports_missing_input_file(
    tmp_path: Path,
    capsys,
) -> None:
    missing = tmp_path / "missing.json"

    exit_code = main(
        [
            "--before",
            str(missing),
            "--after",
            str(missing),
            "--format",
            "json",
        ]
    )

    assert exit_code == 1
    assert f"ERROR: File not found: {missing}" in capsys.readouterr().err
