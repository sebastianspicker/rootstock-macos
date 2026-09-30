#!/usr/bin/env python3
"""Enforce a physical-line ceiling for maintained code files in the worktree."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MAX_LINES = 600
SOURCE_SUFFIXES = {
    ".bash",
    ".c",
    ".cc",
    ".cjs",
    ".cpp",
    ".cypher",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".m",
    ".mjs",
    ".mm",
    ".py",
    ".pyi",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".ts",
    ".tsx",
    ".zsh",
}
EXCLUDED_COMPONENTS = {
    ".build",
    "archive",
    "archives",
    "build",
    "data",
    "dist",
    "fixture",
    "fixtures",
    "generated",
    "node_modules",
    "test-data",
    "test_data",
    "testdata",
    "third_party",
    "vendor",
    "vendors",
}
GENERATED_SUFFIXES = (
    ".bundle.js",
    ".bundle.min.js",
    ".min.js",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check maintained code files for excessive size.")
    parser.add_argument(
        "--max-lines",
        type=int,
        default=DEFAULT_MAX_LINES,
        help=f"maximum physical lines per file (default: {DEFAULT_MAX_LINES})",
    )
    parser.add_argument(
        "--ratchet",
        type=Path,
        help=(
            "JSON file containing exact ceilings for grandfathered files above the new-file limit"
        ),
    )
    args = parser.parse_args()
    if args.max_lines < 1:
        parser.error("--max-lines must be at least 1")
    return args


def load_ratchet(path: Path, *, global_max_lines: int) -> tuple[int, dict[str, int]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read source-size ratchet {path}: {exc}") from exc
    return _validate_ratchet_payload(payload, path, global_max_lines)


def _validate_ratchet_payload(
    payload: object, path: Path, global_max_lines: int
) -> tuple[int, dict[str, int]]:
    ratchet = _ratchet_mapping(payload, path)
    _validate_global_ceiling(ratchet, path, global_max_lines)
    new_file_max_lines = _new_file_ceiling(ratchet, path)
    ceilings = _path_ceilings(ratchet, path, new_file_max_lines, global_max_lines)
    return new_file_max_lines, ceilings


def _ratchet_mapping(payload: object, path: Path) -> dict[str, object]:
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise RuntimeError(f"{path}: expected source-size ratchet version 1")
    return payload


def _validate_global_ceiling(ratchet: dict[str, object], path: Path, global_max_lines: int) -> None:
    if ratchet.get("global_max_lines") != global_max_lines:
        raise RuntimeError(f"{path}: global_max_lines must match --max-lines ({global_max_lines})")


def _new_file_ceiling(ratchet: dict[str, object], path: Path) -> int:
    new_file_max_lines = ratchet.get("new_file_max_lines")
    if not isinstance(new_file_max_lines, int) or new_file_max_lines < 1:
        raise RuntimeError(f"{path}: new_file_max_lines must be a positive integer")
    return new_file_max_lines


def _path_ceilings(
    ratchet: dict[str, object],
    path: Path,
    new_file_max_lines: int,
    global_max_lines: int,
) -> dict[str, int]:
    ceilings = ratchet.get("ceilings")
    if not isinstance(ceilings, dict) or any(
        not isinstance(key, str)
        or not isinstance(value, int)
        or not new_file_max_lines < value <= global_max_lines
        for key, value in ceilings.items()
    ):
        raise RuntimeError(
            f"{path}: ceilings must map paths to integers between "
            f"{new_file_max_lines + 1} and {global_max_lines}"
        )
    return ceilings


def repository_paths() -> list[PurePosixPath]:
    git_executable = shutil.which("git")
    if git_executable is None:
        raise RuntimeError("git executable not found on PATH")
    result = subprocess.run(
        [
            git_executable,
            "-C",
            str(ROOT),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=True,
        capture_output=True,
    )
    return [
        PurePosixPath(raw.decode("utf-8", errors="surrogateescape"))
        for raw in result.stdout.split(b"\0")
        if raw
    ]


def is_maintained_source(path: PurePosixPath) -> bool:
    if path.suffix.casefold() not in SOURCE_SUFFIXES:
        return False
    if any(part.casefold() in EXCLUDED_COMPONENTS for part in path.parts[:-1]):
        return False
    return not path.name.casefold().endswith(GENERATED_SUFFIXES)


def physical_line_count(path: Path) -> int:
    data = path.read_bytes()
    if not data:
        return 0
    return data.count(b"\n") + (not data.endswith(b"\n"))


def _ratchet_settings(args: argparse.Namespace) -> tuple[int | None, dict[str, int]]:
    if args.ratchet is not None:
        return load_ratchet(
            args.ratchet,
            global_max_lines=args.max_lines,
        )
    return None, {}


def _violation_for(
    relative_path: PurePosixPath,
    line_count: int,
    *,
    global_max_lines: int,
    new_file_max_lines: int | None,
    ratchet_ceilings: dict[str, int],
) -> tuple[PurePosixPath, int, int, str] | None:
    if line_count > global_max_lines:
        return relative_path, line_count, global_max_lines, "global ceiling"
    if new_file_max_lines is None or line_count <= new_file_max_lines:
        return None
    ratchet_limit = ratchet_ceilings.get(relative_path.as_posix())
    if ratchet_limit is None:
        return (
            relative_path,
            line_count,
            new_file_max_lines,
            "new or unlisted maintained file",
        )
    if line_count > ratchet_limit:
        return relative_path, line_count, ratchet_limit, "recorded ratchet ceiling"
    return None


def _scan_sources(
    *,
    global_max_lines: int,
    new_file_max_lines: int | None,
    ratchet_ceilings: dict[str, int],
) -> tuple[int, list[tuple[PurePosixPath, int, int, str]]]:
    checked = 0
    violations: list[tuple[PurePosixPath, int, int, str]] = []
    for relative_path in repository_paths():
        if not is_maintained_source(relative_path):
            continue
        absolute_path = ROOT.joinpath(*relative_path.parts)
        if not absolute_path.is_file():
            continue
        checked += 1
        line_count = physical_line_count(absolute_path)
        violation = _violation_for(
            relative_path,
            line_count,
            global_max_lines=global_max_lines,
            new_file_max_lines=new_file_max_lines,
            ratchet_ceilings=ratchet_ceilings,
        )
        if violation is not None:
            violations.append(violation)
    return checked, violations


def _report_violations(
    violations: list[tuple[PurePosixPath, int, int, str]],
) -> int:
    for path, line_count, limit, reason in sorted(violations):
        print(f"{path}: {line_count} lines (limit: {limit}; {reason})")
    print(f"Source size check failed: {len(violations)} violation(s).")
    return 1


def _report_success(checked: int, global_max_lines: int, new_file_max_lines: int | None) -> int:
    new_file_clause = (
        f", with new files capped at {new_file_max_lines} lines."
        if new_file_max_lines is not None
        else "."
    )
    print(
        f"Source size check passed: {checked} maintained files "
        f"at or below {global_max_lines} lines{new_file_clause}"
    )
    return 0


def main() -> int:
    args = parse_args()
    new_file_max_lines, ratchet_ceilings = _ratchet_settings(args)
    checked, violations = _scan_sources(
        global_max_lines=args.max_lines,
        new_file_max_lines=new_file_max_lines,
        ratchet_ceilings=ratchet_ceilings,
    )

    if violations:
        return _report_violations(violations)
    return _report_success(checked, args.max_lines, new_file_max_lines)


if __name__ == "__main__":
    sys.exit(main())
