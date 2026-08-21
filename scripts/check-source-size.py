#!/usr/bin/env python3
"""Enforce a physical-line ceiling for maintained code files in the worktree."""

from __future__ import annotations

import argparse
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
    parser = argparse.ArgumentParser(
        description="Check maintained code files for excessive size."
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=DEFAULT_MAX_LINES,
        help=f"maximum physical lines per file (default: {DEFAULT_MAX_LINES})",
    )
    args = parser.parse_args()
    if args.max_lines < 1:
        parser.error("--max-lines must be at least 1")
    return args


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


def main() -> int:
    args = parse_args()
    checked = 0
    violations: list[tuple[PurePosixPath, int]] = []

    for relative_path in repository_paths():
        if not is_maintained_source(relative_path):
            continue
        absolute_path = ROOT.joinpath(*relative_path.parts)
        if not absolute_path.is_file():
            continue
        checked += 1
        line_count = physical_line_count(absolute_path)
        if line_count > args.max_lines:
            violations.append((relative_path, line_count))

    if violations:
        for path, line_count in sorted(violations):
            print(f"{path}: {line_count} lines (limit: {args.max_lines})")
        print(f"Source size check failed: {len(violations)} violation(s).")
        return 1

    print(
        f"Source size check passed: {checked} maintained files "
        f"at or below {args.max_lines} lines."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
