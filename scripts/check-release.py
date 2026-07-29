#!/usr/bin/env python3
"""Validate Rootstock's public alpha release surface without modifying it."""

from __future__ import annotations

import argparse
import asyncio
import json
import posixpath
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
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


class ReleaseCheck:
    """Aggregate all policy failures so one run reports the complete release delta."""

    def __init__(self) -> None:
        self.failures: list[str] = []

    def require(self, condition: bool, message: str) -> None:
        if condition:
            print(f"PASS: {message}")
        else:
            print(f"FAIL: {message}")
            self.failures.append(message)


def read_text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


async def _run_git_async(
    args: tuple[str, ...], input_text: str | None
) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        "/usr/bin/git",
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


def pep440_alpha(version: str) -> str:
    match = re.fullmatch(r"(\d+\.\d+\.\d+)-alpha\.(\d+)", version)
    if match is None:
        raise ValueError(f"Unsupported public version format: {version}")
    return f"{match.group(1)}a{match.group(2)}"


def check_versions(check: ReleaseCheck, version: str) -> None:
    """Require every Core runtime and package surface to use one alpha identity."""
    python_version = pep440_alpha(version)
    graph = tomllib.loads(read_text("graph/pyproject.toml"))
    cve_scan = tomllib.loads(read_text("modules/cve-scan/pyproject.toml"))
    viewer = json.loads(read_text("package.json"))
    demo_scan = json.loads(read_text("examples/demo-scan.json"))

    check.require(
        f'static let collectorVersion = "{version}"'
        in read_text("collector/Sources/RootstockCLI/RootstockCommand.swift"),
        "Swift collector version matches VERSION",
    )
    check.require(
        f'version="{version}"' in read_text("graph/server.py"),
        "FastAPI version matches VERSION",
    )
    check.require(
        graph["project"]["version"] == python_version,
        "graph package uses the PEP 440 alpha version",
    )
    check.require(
        cve_scan["project"]["version"] == python_version,
        "cve-scan package uses the PEP 440 alpha version",
    )
    check.require(
        f'__version__ = "{python_version}"'
        in read_text("modules/cve-scan/src/cve_scan/__init__.py"),
        "cve-scan runtime version matches package metadata",
    )
    check.require(
        viewer["version"] == version,
        "viewer package version matches VERSION",
    )
    check.require(
        demo_scan["collector_version"] == version,
        "synthetic demo collector version matches VERSION",
    )
    check.require(
        f"## [{version}]" in read_text("CHANGELOG.md"),
        "changelog contains the candidate version",
    )
    check.require(
        f"version: {version}" in read_text("CITATION.cff"),
        "citation metadata matches VERSION",
    )


def _required_public_files() -> tuple[str, ...]:
    return (
        "README.md",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "LICENSE",
        "CITATION.cff",
        "docs/README.md",
        "docs/RELEASING.md",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/release.yml",
        ".node-version",
        "collector/Package.resolved",
        "collector/README.md",
        "graph/uv.lock",
        "modules/cve-scan/uv.lock",
        "package-lock.json",
        "scripts/build-release.sh",
        "scripts/capture-release-screenshots.mjs",
        "scripts/check-release.py",
        "scripts/release-screenshot-fixture.mjs",
        "graph/tests/test_release_screenshot_fixture.py",
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
        "rootstock-red/LICENSE",
        "rootstock-red/NOT_FOR_PRODUCTION_IMPLANT.md",
        "rootstock-blue/Package.swift",
        "rootstock-blue/README.md",
        "rootstock-blue/LICENSE",
        "rootstock-blue/NOTICE",
        "rootstock-blue/Makefile",
        "rootstock-blue/docs/non-goals.md",
    )


def _required_viewer_files() -> tuple[str, ...]:
    return (
        "graph/viewer.py",
        "graph/viewer_template.html",
        "graph/viewer.css",
        "graph/viewer.bundle.js",
        "graph/viewer-src/app.ts",
        "graph/viewer-src/canvas.ts",
        "graph/viewer-src/controls.ts",
        "graph/viewer-src/dom.ts",
        "graph/viewer-src/live.ts",
        "graph/viewer-src/main.ts",
        "graph/viewer-src/model.ts",
        "graph/viewer-src/protocol.ts",
        "graph/viewer-src/runtime.ts",
        "graph/viewer-src/spatial.ts",
        "graph/viewer-src/storage.ts",
        "graph/viewer-src/types.ts",
        "graph/viewer-src/view.ts",
    )


def _expected_screenshots() -> set[str]:
    return {
        "viewer-overview.png",
        "viewer-node-inspector.png",
        "viewer-attack-path.png",
        "viewer-risk-filter.png",
    }


def _ignored_screenshots(expected_screenshots: set[str]) -> list[str]:
    _, stdout, _ = _run_git(
        "check-ignore",
        "--stdin",
        input_text="\n".join(
            f"docs/screenshots/{name}" for name in expected_screenshots
        ),
    )
    return stdout.splitlines()


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
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(markdown_path), target)
            )
            if resolved not in tracked_paths:
                failures.append(f"{markdown_path} -> {target}")
    return failures


def _local_markdown_image_target(raw_target: str | None) -> str | None:
    target = unquote(raw_target or "").split("#", 1)[0].split("?", 1)[0]
    if not target or target.startswith(("/", "data:", "http:", "https:")):
        return None
    return target


def check_public_files(check: ReleaseCheck) -> None:
    """Check required metadata, locks, screenshots, and integrity-backed browser CI."""
    tracked_paths = _tracked_paths()
    _check_tracked_public_files(check, tracked_paths)
    _check_public_screenshots(check, tracked_paths)
    _check_browser_release_integrity(check)
    _report_paths(check, _index_markdown_image_failures(tracked_paths), "all index-level Markdown image targets are Git-tracked", "missing index image")


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


def _check_public_screenshots(check: ReleaseCheck, tracked_paths: set[str]) -> None:
    expected_screenshots = _expected_screenshots()
    screenshots = {
        path.name for path in (ROOT / "docs/screenshots").glob("*.png")
    }
    check.require(
        screenshots == expected_screenshots,
        "the curated public screenshot set is exact",
    )
    tracked_screenshots = {
        Path(path).name
        for path in tracked_paths
        if path.startswith("docs/screenshots/") and path.endswith(".png")
    }
    check.require(
        tracked_screenshots == expected_screenshots,
        "the curated public screenshot set is Git-tracked and exact",
    )

    ignored = _ignored_screenshots(expected_screenshots)
    check.require(
        not ignored,
        "curated public screenshots are not hidden by .gitignore",
    )


def _check_browser_release_integrity(check: ReleaseCheck) -> None:
    workflow = read_text(".github/workflows/test.yml")
    check.require(
        "npm ci" in workflow and "npm install --no-package-lock" not in workflow,
        "browser CI uses the integrity-backed npm lock",
    )

    release_script = read_text("scripts/build-release.sh")
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
        if path.startswith(FORBIDDEN_TRACKED_PREFIXES)
        or (
            "/" not in path
            and (
                path.casefold() in FORBIDDEN_ROOT_BASENAMES
                or FORBIDDEN_ROOT_ARTIFACT.fullmatch(path)
            )
        )
    ]


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


def check_git_hygiene(check: ReleaseCheck, require_clean: bool) -> None:
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

    tracked_ignored = git_output("ls-files", "-ci", "--exclude-standard").splitlines()
    check.require(
        not tracked_ignored,
        "no tracked path is hidden by .gitignore",
    )
    for path in tracked_ignored:
        print(f"  tracked and ignored: {path}")

    if require_clean:
        status = git_output("status", "--porcelain")
        check.require(not status, "working tree is clean for tagging")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="also fail when the working tree has staged, unstaged, or untracked changes",
    )
    args = parser.parse_args()

    check = ReleaseCheck()
    version = read_text("VERSION").strip()
    check.require(
        re.fullmatch(r"\d+\.\d+\.\d+-alpha\.\d+", version) is not None,
        "VERSION is a supported semantic alpha version",
    )
    check_versions(check, version)
    check_public_files(check)
    check_git_hygiene(check, args.require_clean)

    if check.failures:
        print(f"\nRelease surface failed {len(check.failures)} check(s).")
        return 1
    print("\nRelease surface checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
