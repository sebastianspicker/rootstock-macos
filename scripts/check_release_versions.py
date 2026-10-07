"""Version, lockfile, and changelog checks for scripts/check-release.py."""

from __future__ import annotations

import datetime
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY_URL = "https://github.com/sebastianspicker/rootstock-macos"
RELEASE_DATE = re.compile(
    r"^date-released:\s*['\"]?(\d{4}-\d{2}-\d{2})['\"]?\s*$",
    re.MULTILINE,
)


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
    viewer = json.loads(read_text("graph/viewer/package.json"))
    repo_tools = json.loads(read_text("package.json"))
    demo_scan = json.loads(read_text("examples/demo-scan.json"))

    check.require(
        f'static let collectorVersion = "{version}"'
        in read_text("collector/Sources/RootstockCLI/RootstockCommand.swift"),
        "Swift collector version matches VERSION",
    )
    check.require(
        f'version="{version}"' in read_text("graph/src/rootstock_graph/api.py"),
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
        repo_tools["version"] == version,
        "repository tools package version matches VERSION",
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


def _uv_lock_version(path: str, package: str) -> str | None:
    """Return the version of one `[[package]]` entry in a uv.lock file."""
    match = re.search(
        rf'^\[\[package\]\]\nname = "{re.escape(package)}"\nversion = "([^"]+)"',
        read_text(path),
        re.MULTILINE,
    )
    return match.group(1) if match else None


def check_lockfiles_and_links(check: ReleaseCheck, version: str) -> None:
    """Require lockfile versions and the changelog link target to track VERSION."""
    python_version = pep440_alpha(version)
    for path in ("package-lock.json", "graph/viewer/package-lock.json"):
        check.require(
            json.loads(read_text(path)).get("version") == version,
            f"{path} version matches VERSION",
        )
    for project, lock in (
        ("graph", "graph/uv.lock"),
        ("modules/cve-scan", "modules/cve-scan/uv.lock"),
    ):
        name = tomllib.loads(read_text(f"{project}/pyproject.toml"))["project"]["name"]
        check.require(
            _uv_lock_version(lock, name) == python_version,
            f"{lock} entry for {name} matches the PEP 440 alpha version",
        )
    reference = re.search(
        rf"^\[{re.escape(version)}\]:\s*(\S+)", read_text("CHANGELOG.md"), re.MULTILINE
    )
    target = reference.group(1) if reference else ""
    check.require(
        target == REPOSITORY_URL or target.startswith(f"{REPOSITORY_URL}/"),
        "changelog link reference for the current version points at the project repository",
    )


def check_citation_release_date(check: ReleaseCheck) -> None:
    match = RELEASE_DATE.search(read_text("CITATION.cff"))
    valid = False
    if match:
        try:
            released = datetime.date.fromisoformat(match.group(1))
            valid = released <= datetime.date.today()
        except ValueError:
            valid = False
    check.require(valid, "CITATION.cff has a real, non-future YYYY-MM-DD date-released value")
