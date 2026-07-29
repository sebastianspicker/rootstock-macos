"""Classify family findings without coupling graph exports to report rendering."""

from __future__ import annotations


def is_red_family_finding(finding: dict, finding_id: str, source: str | None) -> bool:
    family_source = str(
        finding.get("source")
        or finding.get("family_source")
        or source
        or finding.get("kind")
        or ""
    ).lower()
    if is_red_family_source(family_source):
        return True
    if is_blue_family_source(family_source):
        return False
    lower_id = finding_id.lower()
    return not (lower_id.startswith(("harden.", "sample.")) or "control" in lower_id)


def is_red_family_source(source: str) -> bool:
    return "red" in source or source.endswith("rootstock-red") or "rs_red" in source


def is_blue_family_source(source: str) -> bool:
    return "blue" in source or source.endswith("rootstock-blue") or "rs_blue" in source
