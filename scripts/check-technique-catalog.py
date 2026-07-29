#!/usr/bin/env python3
"""Validate docs/references/technique-catalog.yaml reference integrity.

Checks:
  - YAML parses and has >= 15 techniques
  - graph_queries basenames exist under graph/queries/
  - blue_detections basenames exist under rootstock-blue/Content/detections/samples/
  - red_findings IDs appear as string literals under rootstock-red/Sources/

Entries with status ``planned`` skip missing-reference failures for empty mappings
but still require an id/title.

Usage:
    python3 scripts/check-technique-catalog.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "docs" / "references" / "technique-catalog.yaml"
QUERIES = ROOT / "graph" / "queries"
BLUE_DET = ROOT / "rootstock-blue" / "Content" / "detections" / "samples"
RED_SRC = ROOT / "rootstock-red" / "Sources"
MIN_TECHNIQUES = 15


def load_yaml(path: Path) -> dict:
    try:
        import yaml  # type: ignore
    except ImportError:
        # Minimal subset parser for our catalog shape (no PyYAML required).
        return _load_yaml_minimal(path.read_text(encoding="utf-8"))
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("catalog root must be a mapping")
    return data


class _MinimalCatalogParser:
    """Parse the catalog subset needed when PyYAML is unavailable."""

    _mapping_keys = ("graph_queries", "red_findings", "blue_detections")

    def __init__(self) -> None:
        self.techniques: list[dict] = []
        self.version = 1
        self.current: dict | None = None
        self.section: str | None = None
        self.list_key: str | None = None
        self.depth_lines: list[str] = []
        self.in_depth = False

    def parse(self, text: str) -> dict:
        for raw in (line for line in text.splitlines() if not line.strip().startswith("#")):
            self._consume(raw)
        self._flush_depth()
        self._finish_technique()
        return {"version": self.version, "techniques": self.techniques}

    def _consume(self, raw: str) -> None:
        if not raw.strip():
            self._append_depth_blank()
        elif self._set_version(raw) or raw.startswith("techniques:"):
            return
        elif self._start_technique(raw):
            return
        elif self.current is not None:
            self._consume_current(raw)

    def _consume_current(self, raw: str) -> None:
        if self._start_depth_notes(raw) or self._consume_depth_text(raw):
            return
        if self._set_scalar(raw, "title") or self._set_scalar(raw, "status"):
            return
        if re.match(r"^\s+mappings:\s*$", raw):
            self.section, self.list_key = "mappings", None
            return
        self._append_mapping_value(raw)

    def _set_version(self, raw: str) -> bool:
        match = re.match(r"^version:\s*(\d+)\s*$", raw)
        if match is None:
            return False
        self.version = int(match.group(1))
        return True

    def _start_technique(self, raw: str) -> bool:
        match = re.match(r"^\s*-\s*id:\s*(.+)\s*$", raw)
        if match is None:
            return False
        self._flush_depth()
        self._finish_technique()
        self.current = {
            "id": self._unquote(match.group(1)),
            "mappings": {key: [] for key in self._mapping_keys},
        }
        self.section, self.list_key = None, None
        return True

    def _start_depth_notes(self, raw: str) -> bool:
        if not re.match(r"^\s+depth_notes:\s*\|", raw):
            return False
        self._flush_depth()
        self.in_depth = True
        self.list_key, self.section = None, None
        return True

    def _consume_depth_text(self, raw: str) -> bool:
        if not self.in_depth:
            return False
        if re.match(r"^\s{4}(title|attack_techniques|surfaces|mappings|status|id):", raw):
            self._flush_depth()
            return False
        self.depth_lines.append(raw.strip())
        return True

    def _set_scalar(self, raw: str, key: str) -> bool:
        match = re.match(rf"^\s+{key}:\s*(.+)\s*$", raw)
        if match is None or self.current is None:
            return False
        self.current[key] = self._unquote(match.group(1))
        return True

    def _append_mapping_value(self, raw: str) -> None:
        key_match = re.match(r"^\s+(graph_queries|red_findings|blue_detections):\s*$", raw)
        if key_match:
            self.list_key = key_match.group(1)
            return
        value_match = re.match(r"^\s+-\s+(.+)\s*$", raw)
        if value_match and self.list_key and self.section == "mappings" and self.current:
            self.current["mappings"][self.list_key].append(self._unquote(value_match.group(1)))

    def _append_depth_blank(self) -> None:
        if self.in_depth:
            self.depth_lines.append("")

    def _flush_depth(self) -> None:
        if self.current is not None and self.in_depth:
            self.current["depth_notes"] = "\n".join(self.depth_lines).strip()
        self.depth_lines, self.in_depth = [], False

    def _finish_technique(self) -> None:
        if self.current is not None:
            self.techniques.append(self.current)
            self.current = None

    @staticmethod
    def _unquote(value: str) -> str:
        return value.strip().strip(chr(39) + chr(34))


def _load_yaml_minimal(text: str) -> dict:
    """Parse the technique catalog without PyYAML."""
    return _MinimalCatalogParser().parse(text)


def collect_red_ids() -> set[str]:
    ids: set[str] = set()
    if not RED_SRC.is_dir():
        return ids
    pat = re.compile(
        r'["\'](rootstock\.(?:vector|check)\.[a-zA-Z0-9_.]+)["\']'
    )
    for path in RED_SRC.rglob("*.swift"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        ids.update(pat.findall(text))
    return ids


def _catalog_errors(techniques: list[dict], red_ids: set[str]) -> list[str]:
    errors: list[str] = []
    seen_ids: set[str] = set()
    for technique in techniques:
        _validate_technique(technique, red_ids, seen_ids, errors)
    return errors


def _validate_technique(
    technique: dict,
    red_ids: set[str],
    seen_ids: set[str],
    errors: list[str],
) -> None:
    technique_id = _record_technique_id(technique, seen_ids, errors)
    if technique_id is None:
        return
    _validate_technique_title(technique, technique_id, errors)
    if technique.get("status", "mapped") == "planned":
        return
    mappings = technique.get("mappings") or {}
    _validate_mapping_paths(technique_id, mappings, "graph_queries", QUERIES, "", errors)
    _validate_mapping_paths(technique_id, mappings, "blue_detections", BLUE_DET, ".yaml", errors)
    _validate_red_findings(technique_id, mappings, red_ids, errors)


def _record_technique_id(technique: dict, seen_ids: set[str], errors: list[str]) -> str | None:
    technique_id = technique.get("id")
    if not technique_id:
        errors.append("technique missing id")
        return None
    if technique_id in seen_ids:
        errors.append(f"duplicate id: {technique_id}")
    seen_ids.add(technique_id)
    return technique_id


def _validate_technique_title(technique: dict, technique_id: str, errors: list[str]) -> None:
    if not technique.get("title"):
        errors.append(f"{technique_id}: missing title")


def _validate_red_findings(
    technique_id: str, mappings: dict, red_ids: set[str], errors: list[str]
) -> None:
    for finding_id in mappings.get("red_findings") or []:
        if finding_id not in red_ids:
            errors.append(f"{technique_id}: red finding id not found in Sources: {finding_id}")


def _validate_mapping_paths(
    technique_id: str,
    mappings: dict,
    mapping_key: str,
    directory: Path,
    suffix: str,
    errors: list[str],
) -> None:
    for item in mappings.get(mapping_key) or []:
        if not (directory / f"{item}{suffix}").is_file():
            label = mapping_key.replace("_", " ").removesuffix("s")
            errors.append(f"{technique_id}: missing {label} {item}{suffix}")


def _print_errors(errors: list[str]) -> None:
    if errors:
        print("Technique catalog check FAILED:")
        for error in errors:
            print(f"  - {error}")


def main() -> int:
    if not CATALOG.is_file():
        print(f"ERROR: catalog not found: {CATALOG}", file=sys.stderr)
        return 1

    try:
        data = load_yaml(CATALOG)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: failed to parse catalog: {exc}", file=sys.stderr)
        return 1

    techniques = data.get("techniques") or []
    if len(techniques) < MIN_TECHNIQUES:
        print(
            f"ERROR: expected >= {MIN_TECHNIQUES} techniques, found {len(techniques)}",
            file=sys.stderr,
        )
        return 1

    errors = _catalog_errors(techniques, collect_red_ids())
    if errors:
        _print_errors(errors)
        return 1

    print(
        f"OK: {len(techniques)} techniques; "
        f"graph/red/blue references resolve (status≠planned enforced)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
