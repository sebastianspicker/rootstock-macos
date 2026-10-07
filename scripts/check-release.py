#!/usr/bin/env python3
"""Validate Rootstock's public alpha release surface without modifying it."""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    raise SystemExit(
        "scripts/check-release.py requires Python 3.11 or newer (its version checks use tomllib); "
        f"found {sys.version.split()[0]}"
    )

import argparse
import asyncio
import os
import posixpath
import re
import shutil
from pathlib import Path
from urllib.parse import unquote

from check_release_versions import (
    ROOT,
    ReleaseCheck,
    check_citation_release_date,
    check_lockfiles_and_links,
    check_versions,
    read_text,
)

GIT = shutil.which("git") or "git"
PRIVATE_TEST_PATHS = (
    "collector/Tests/",
    "graph/tests/",
    "graph/viewer/tests/",
    "graph/viewer/scripts/test-viewer.mjs",
    "modules/cve-scan/tests/",
    "packages/RootstockMacFacts/Tests/",
    "rootstock-blue/Tests/",
    "rootstock-red/Tests/",
)
FORBIDDEN_TRACKED_PREFIXES = (
    "docs/archive/",
    "docs/deprecated/",
    "docs/private/",
    "docs/generated/",
)
FORBIDDEN_ROOT_BASENAMES = {
    "agent.md",
    "analysis.md",
    "audit.md",
    "handoff.md",
    "ledger.md",
    "plan.md",
    "remediation.md",
    "review.md",
    "security_review.md",
    "status.md",
}
FORBIDDEN_ROOT_ARTIFACT = re.compile(
    r"^(?:.*[-_](?:AGENT|ANALYSIS|PLAN|STATUS|LEDGER|HANDOFF|AUDIT|REVIEW)|"
    r".*[-_]remediation.*)\.md$",
    re.IGNORECASE,
)
MARKDOWN_IMAGE = re.compile(r"!\[[^]]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+[^)]*)?\)")


async def _run_git_async(args: tuple[str, ...], input_text: str | None) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        GIT,
        "-C",
        str(ROOT),
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate(
        input_text.encode() if input_text is not None else None
    )
    return process.returncode, stdout.decode(), stderr.decode()


def _run_git(*args: str, input_text: str | None = None) -> tuple[int, str, str]:
    return asyncio.run(_run_git_async(args, input_text))


def git_output(*args: str) -> str:
    status, stdout, stderr = _run_git(*args)
    if status != 0:
        raise RuntimeError(stderr.strip() or f"git exited with status {status}")
    return stdout


def _required_public_files() -> tuple[str, ...]:
    return (
        "README.md",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "LICENSE",
        "CITATION.cff",
        "modules/cve-scan/LICENSE",
        "modules/cve-scan/SECURITY.md",
        "packages/RootstockMacFacts/LICENSE",
        "rootstock-blue/LICENSE",
        "rootstock-blue/NOTICE",
        "rootstock-blue/SECURITY.md",
        "rootstock-red/ACCEPTABLE_USE.md",
        "rootstock-red/LICENSE",
        "rootstock-red/SECURITY.md",
        "docs/README.md",
        "docs/RELEASING.md",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/release.yml",
        ".github/workflows/pages.yml",
        "graph/viewer/.node-version",
        "collector/Package.resolved",
        "collector/README.md",
        "graph/uv.lock",
        "modules/cve-scan/uv.lock",
        "package-lock.json",
        "package.json",
        "graph/viewer/package-lock.json",
        "graph/viewer/scripts/build-pages-demo.mjs",
        "graph/viewer/scripts/demo-tour.mjs",
        "graph/viewer/scripts/capture-demo-screenshots.mjs",
        "docs/screenshots.md",
        "docs/assets/screenshots/scope.png",
        "docs/assets/screenshots/evidence.png",
        "docs/assets/screenshots/report.png",
        "docs/assets/screenshots/graph.png",
        "collector/scripts/build-release.sh",
        "graph/viewer/scripts/check-pages-demo.mjs",
        "scripts/check-release.py",
        "scripts/verify",
        "graph/viewer/scripts/viewer-demo-data.mjs",
    )


def _required_pillar_files() -> tuple[str, ...]:
    """Return the small set of files that makes each public pillar identifiable."""
    return (
        "docs/FAMILY.md",
        "packages/RootstockMacFacts/Package.swift",
        "packages/RootstockMacFacts/README.md",
        "rootstock-red/Package.swift",
        "rootstock-red/Package.resolved",
        "rootstock-red/README.md",
        "rootstock-red/NOT_FOR_PRODUCTION_IMPLANT.md",
        "rootstock-blue/Package.swift",
        "rootstock-blue/README.md",
        "rootstock-blue/Makefile",
        "rootstock-blue/docs/non-goals.md",
    )


def _required_viewer_files() -> tuple[str, ...]:
    return (
        "graph/src/rootstock_graph/reporting/viewer.py",
        "graph/src/rootstock_graph/resources/viewer/viewer_template.html",
        "graph/src/rootstock_graph/resources/viewer/viewer.css",
        "graph/src/rootstock_graph/resources/viewer/viewer.bundle.js",
        "graph/viewer/src/app.ts",
        "graph/viewer/src/canvas.ts",
        "graph/viewer/src/controls.ts",
        "graph/viewer/src/dom.ts",
        "graph/viewer/src/live.ts",
        "graph/viewer/src/main.ts",
        "graph/viewer/src/model.ts",
        "graph/viewer/src/protocol.ts",
        "graph/viewer/src/runtime.ts",
        "graph/viewer/src/spatial.ts",
        "graph/viewer/src/storage.ts",
        "graph/viewer/src/types.ts",
        "graph/viewer/src/view.ts",
    )


def _tracked_paths() -> set[str]:
    return set(git_output("ls-files").splitlines())


def _index_markdown_image_failures(tracked_paths: set[str]) -> list[str]:
    """Find local Markdown image targets absent from the Git index.

    The release gate deliberately reads Markdown from the index rather than the
    working tree. This detects a staged asset deletion even when a replacement
    file has been generated locally but has not been added to Git.
    """
    failures: list[str] = []
    markdown_paths = sorted(
        path for path in tracked_paths if path.casefold().endswith((".md", ".mdx"))
    )
    for markdown_path in markdown_paths:
        text = git_output("show", f":{markdown_path}")
        for match in MARKDOWN_IMAGE.finditer(text):
            target = _local_markdown_image_target(match.group(1) or match.group(2))
            if target is None:
                continue
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(markdown_path), target))
            if resolved not in tracked_paths:
                failures.append(f"{markdown_path} -> {target}")
    return failures


def _local_markdown_image_target(raw_target: str | None) -> str | None:
    target = unquote(raw_target or "").split("#", 1)[0].split("?", 1)[0]
    if not target or target.startswith(("/", "data:", "http:", "https:")):
        return None
    return target


def check_public_files(check: ReleaseCheck) -> None:
    """Check required metadata, locks, and documentation integrity."""
    tracked_paths = _tracked_paths()
    _check_tracked_public_files(check, tracked_paths)
    _check_release_integrity(check)
    _report_paths(
        check,
        _index_markdown_image_failures(tracked_paths),
        "all index-level Markdown image targets are Git-tracked",
        "missing index image",
    )


def _check_tracked_public_files(check: ReleaseCheck, tracked_paths: set[str]) -> None:
    for path in _required_public_files():
        check.require((ROOT / path).is_file(), f"required public file exists: {path}")
        check.require(path in tracked_paths, f"required public file is Git-tracked: {path}")
    for path in _required_pillar_files():
        check.require((ROOT / path).is_file(), f"public pillar marker exists: {path}")
        check.require(path in tracked_paths, f"public pillar marker is Git-tracked: {path}")
    shared_license = "packages/RootstockMacFacts/LICENSE"
    check.require(
        (ROOT / shared_license).is_file(),
        "RootstockMacFacts has an explicit license file",
    )
    check.require(
        shared_license in tracked_paths,
        "RootstockMacFacts license file is Git-tracked",
    )
    for path in _required_viewer_files():
        check.require((ROOT / path).is_file(), f"viewer source or bundle exists: {path}")
        check.require(path in tracked_paths, f"viewer source or bundle is Git-tracked: {path}")


def _check_release_integrity(check: ReleaseCheck) -> None:
    release_script = read_text("collector/scripts/build-release.sh")
    check.require(
        '"${REPO_ROOT}/collector/README.md"' in release_script
        and '"${REPO_ROOT}/README.md" "${PACKAGE_DIR}/README.md"' not in release_script,
        "collector archive uses its self-contained README",
    )
    check.require(
        "EXPECTED_ARCHIVE_LISTING" in release_script,
        "collector archive validates its exact file set",
    )


def _forbidden_tracked_paths() -> list[str]:
    return [
        path
        for path in git_output("ls-files").splitlines()
        if path
        if _is_forbidden_tracked_path(path)
    ]


def _is_forbidden_tracked_path(path: str) -> bool:
    if path.startswith(FORBIDDEN_TRACKED_PREFIXES + PRIVATE_TEST_PATHS):
        return True
    if "/" in path:
        return False
    return (
        path.casefold() in FORBIDDEN_ROOT_BASENAMES
        or FORBIDDEN_ROOT_ARTIFACT.fullmatch(path) is not None
    )


def _local_root_artifacts() -> list[str]:
    artifacts: list[str] = []
    for path in ROOT.iterdir():
        name = path.name
        if (
            name.casefold() not in FORBIDDEN_ROOT_BASENAMES
            and not FORBIDDEN_ROOT_ARTIFACT.fullmatch(name)
        ):
            continue
        try:
            if path.is_file():
                artifacts.append(name)
        except OSError:
            artifacts.append(name)
    return artifacts


def _local_packets() -> list[str]:
    return [
        path.relative_to(ROOT).as_posix()
        for prefix in FORBIDDEN_TRACKED_PREFIXES
        for path in (ROOT / prefix).rglob("*")
        if path.is_file()
    ]


def _report_paths(check: ReleaseCheck, paths: list[str], message: str, prefix: str) -> None:
    check.require(not paths, message)
    for path in paths:
        print(f"  {prefix}: {path}")


def _check_tracked_ignored_paths(check: ReleaseCheck) -> None:
    tracked_ignored = git_output("ls-files", "-ci", "--exclude-standard").splitlines()
    check.require(not tracked_ignored, "no tracked path is hidden by .gitignore")
    for path in tracked_ignored:
        print(f"  tracked and ignored: {path}")


def _check_candidate_index(check: ReleaseCheck, status: str) -> None:
    configured_index = os.environ.get("GIT_INDEX_FILE", "")
    index_path = Path(configured_index).expanduser()
    if configured_index and not index_path.is_absolute():
        index_path = ROOT / index_path
    using_temporary_index = bool(configured_index) and (
        index_path.resolve() != (ROOT / ".git" / "index").resolve()
    )
    worktree_clean = all(
        len(line) >= 2 and line[1] == " " and line[:2] != "??" for line in status.splitlines()
    )
    check.require(using_temporary_index, "candidate proof uses a temporary Git index")
    check.require(worktree_clean, "candidate index exactly matches the working tree")


def check_git_hygiene(check: ReleaseCheck, require_clean: bool, candidate_index: bool) -> None:
    """Reject private working files and optionally enforce a tag-clean tree."""
    _report_paths(
        check,
        _forbidden_tracked_paths(),
        "no tracked private working files",
        "forbidden",
    )
    _report_paths(
        check,
        _local_root_artifacts(),
        "no local private working files",
        "local root packet",
    )
    _report_paths(
        check,
        _local_packets(),
        "ignored private working directories are empty",
        "local packet",
    )
    _check_tracked_ignored_paths(check)
    if not require_clean:
        return

    status = git_output("status", "--porcelain")
    if candidate_index:
        _check_candidate_index(check, status)
        return
    check.require(not status, "working tree is clean for tagging")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="also fail when the working tree has staged, unstaged, or untracked changes",
    )
    parser.add_argument(
        "--candidate-index",
        action="store_true",
        help="accept staged candidate changes only when GIT_INDEX_FILE matches the tree",
    )
    parser.add_argument(
        "--for-tag",
        action="store_true",
        help="also require release-only metadata such as the CITATION.cff release date",
    )
    args = parser.parse_args()
    if args.candidate_index and not args.require_clean:
        parser.error("--candidate-index requires --require-clean")

    check = ReleaseCheck()
    version = read_text("VERSION").strip()
    check.require(
        re.fullmatch(r"\d+\.\d+\.\d+-alpha\.\d+", version) is not None,
        "VERSION is a supported semantic alpha version",
    )
    check_versions(check, version)
    check_lockfiles_and_links(check, version)
    if args.for_tag:
        check_citation_release_date(check)
    check_public_files(check)
    check_git_hygiene(check, args.require_clean, args.candidate_index)

    if check.failures:
        print(f"\nRelease surface failed {len(check.failures)} check(s).")
        return 1
    print("\nRelease surface checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
