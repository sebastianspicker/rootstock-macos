"""
version_matcher.py — Version-aware vulnerability matching for Rootstock.

Parses Apple-style version strings ("macOS 14.6 and earlier") and semver-like
application versions ("127.0.6533.72"), then determines whether a given
application version falls within the affected range of a CVE.

Key rules:
  - None app version → assume affected (conservative)
  - None affected_versions → assume affected (no data to exclude)
  - Multi-platform strings are parsed per-platform (macOS extracted first)
"""

from __future__ import annotations

import re


# ── Version parsing ──────────────────────────────────────────────────────────

_PRE_RELEASE_RE = re.compile(r"(\d+)\s*(alpha|beta|rc|dev|a|b)(\d*)", re.IGNORECASE)
_SEMVER_PRE_RELEASE_RE = re.compile(
    r"^(dev|alpha|a|beta|b|rc)(?:[.\s-]?(\d+))?$",
    re.IGNORECASE,
)
_PRE_RANK = {"dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2, "rc": -1}


def parse_version_tuple(version_str: str) -> tuple[int, ...]:
    """Parse a dotted version string into a comparable int tuple.

    Pre-release suffixes (alpha, beta, rc, dev) sort before the corresponding
    release: ``"15beta3"`` → ``(15, -2, 3)`` which is less than ``(15,)`` because
    the pre-release sentinel (-4..-1) is negative.

    Pre-release ordering: dev (-4) < alpha (-3) < beta (-2) < rc (-1) < release (0).

    Examples:
        "14.6"        → (14, 6)
        "127.0.6533.72" → (127, 0, 6533, 72)
        "15"          → (15,)
        "15beta3"     → (15, -2, 3)
        "15.0alpha1"  → (15, 0, -3, 1)
        "1.0.0-rc.1"  → (1, 0, 0, -1, 1)
    """
    version = version_str.strip().split("+", 1)[0].strip()
    base_version, has_semver_suffix, semver_suffix = version.partition("-")

    parts = _parse_base_version_parts(base_version)
    if not parts:
        raise ValueError(f"Cannot parse version: {version_str!r}")

    if has_semver_suffix:
        parts.extend(_parse_semver_suffix(semver_suffix, version_str))

    return tuple(parts)


def _parse_base_version_parts(base_version: str) -> list[int]:
    parts: list[int] = []
    for segment in base_version.split("."):
        parts.extend(_parse_base_version_segment(segment))
    return parts


def _parse_base_version_segment(segment: str) -> list[int]:
    pre = _PRE_RELEASE_RE.match(segment)
    if pre:
        parts = [int(pre.group(1)), _PRE_RANK[pre.group(2).lower()]]
        if pre.group(3):
            parts.append(int(pre.group(3)))
        return parts

    m = re.match(r"(\d+)", segment)
    if m:
        return [int(m.group(1))]
    return []


def _parse_semver_suffix(semver_suffix: str, version_str: str) -> list[int]:
    pre = _SEMVER_PRE_RELEASE_RE.match(semver_suffix.strip())
    if pre is None:
        raise ValueError(f"Cannot parse pre-release version: {version_str!r}")

    parts = [_PRE_RANK[pre.group(1).lower()]]
    if pre.group(2):
        parts.append(int(pre.group(2)))
    return parts


def _compare_versions(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compare two version tuples.  Returns -1, 0, or 1."""
    max_len = max(len(a), len(b))
    # Pad shorter tuple with zeros for comparison
    a_padded = a + (0,) * (max_len - len(a))
    b_padded = b + (0,) * (max_len - len(b))
    if a_padded < b_padded:
        return -1
    elif a_padded > b_padded:
        return 1
    return 0


def version_lte(version, ceiling) -> bool:
    """Return True if *version* <= *ceiling*.

    Accepts either raw strings or pre-parsed tuples.
    """
    a = version if isinstance(version, tuple) else parse_version_tuple(version)
    b = ceiling if isinstance(ceiling, tuple) else parse_version_tuple(ceiling)
    return _compare_versions(a, b) <= 0


def version_lt(version: str, ceiling: str) -> bool:
    """Return True if *version* < *ceiling*."""
    return _compare_versions(parse_version_tuple(version), parse_version_tuple(ceiling)) < 0


# ── Apple-style affected_versions parsing ────────────────────────────────────

# Matches patterns like:
#   "macOS 14.6 and earlier"
#   "macOS 15.1 and earlier"
#   "macOS 13.5 and earlier, iOS 16.6 and earlier"
_MACOS_AND_EARLIER_RE = re.compile(
    r"macOS\s+([\d.]+)\s+and\s+earlier",
    re.IGNORECASE,
)

# Matches patterns like "Electron < 27.1.0"
_LESS_THAN_RE = re.compile(
    r"<\s*([\d.]+)",
)

# Matches bare version ceiling when patched_version has the answer
_MACOS_VERSION_RE = re.compile(
    r"macOS\s+([\d.]+)",
    re.IGNORECASE,
)


def extract_macos_max_version(affected_versions: str) -> str | None:
    """Extract the maximum affected macOS version from an affected_versions string.

    Returns the version ceiling (the max version that IS affected), or None
    if the string doesn't contain a parseable macOS version pattern.

    Examples:
        "macOS 14.6 and earlier"                    → "14.6"
        "macOS 15.1 and earlier"                    → "15.1"
        "macOS 13.5 and earlier, iOS 16.6 and earlier" → "13.5"
        "macOS 15 and earlier, iOS 18 and earlier"  → "15"
    """
    m = _MACOS_AND_EARLIER_RE.search(affected_versions)
    if m:
        return m.group(1)
    return None


def extract_app_max_version(affected_versions: str) -> str | None:
    """Extract a non-macOS version ceiling from affected_versions.

    Handles patterns like "Electron < 27.1.0", "< 4.5.0", etc.
    Returns the exclusive upper bound (app must be < this to be affected).
    """
    m = _LESS_THAN_RE.search(affected_versions)
    if m:
        return m.group(1)
    return None


def extract_patched_macos_version(patched_version: str | None) -> str | None:
    """Extract a macOS version number from a patched_version string.

    Examples:
        "macOS 14.7"        → "14.7"
        "macOS 15.2"        → "15.2"
        "macOS 13.5.2, iOS 16.6.1" → "13.5.2"
    """
    if not patched_version:
        return None
    m = _MACOS_VERSION_RE.search(patched_version)
    if m:
        return m.group(1)
    return None


# ── Main matching logic ──────────────────────────────────────────────────────

def is_affected(
    app_version: str | None,
    affected_versions: str,
    patched_version: str | None,
    *,
    is_macos_cve: bool = False,
    macos_version: str | None = None,
) -> bool:
    """Determine whether an application is affected by a CVE based on version info.

    Parameters
    ----------
    app_version:
        The application's version string, or None if unknown.
    affected_versions:
        The CVE's affected_versions field (freetext from registry).
    patched_version:
        The CVE's patched_version field, or None.
    is_macos_cve:
        If True, this is a macOS-level CVE — match against macos_version
        instead of app_version.
    macos_version:
        The macOS version of the scanned host (from Computer node).

    Returns
    -------
    bool:
        True if the app/system should be considered affected.

    Conservative defaults:
        - None app_version → True (assume affected)
        - Unparseable strings → True (assume affected)
    """
    # macOS-level CVE: check the host OS version, not the app version
    if is_macos_cve:
        return _is_macos_affected(macos_version, affected_versions, patched_version)

    # App-level CVE with no app version → assume affected
    if app_version is None:
        return True

    return _is_app_affected(app_version, affected_versions, patched_version)


def _is_macos_affected(
    macos_version: str | None,
    affected_versions: str,
    patched_version: str | None,
) -> bool:
    if macos_version is None:
        return True
    max_ver = extract_macos_max_version(affected_versions)
    if max_ver is not None:
        return _conservative_compare(version_lte, macos_version, max_ver)
    patched_ver = extract_patched_macos_version(patched_version)
    if patched_ver is not None:
        return _conservative_compare(version_lt, macos_version, patched_ver)
    return True


def _is_app_affected(
    app_version: str,
    affected_versions: str,
    patched_version: str | None,
) -> bool:
    app_ceiling = extract_app_max_version(affected_versions)
    if app_ceiling is not None:
        return _conservative_compare(version_lt, app_version, app_ceiling)
    max_ver = extract_macos_max_version(affected_versions)
    if max_ver is not None:
        return _conservative_compare(version_lte, app_version, max_ver)
    patched_ver = extract_patched_macos_version(patched_version)
    if patched_ver is not None:
        return _conservative_compare(version_lt, app_version, patched_ver)
    return True


def _conservative_compare(compare, version: str, ceiling: str) -> bool:
    try:
        return compare(version, ceiling)
    except ValueError:
        return True
