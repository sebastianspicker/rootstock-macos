"""bounded_json.py - Read untrusted JSON input with size and shape limits.

Every failure mode of reading a JSON file (not a regular file, too large, unreadable,
undecodable, malformed, nested too deeply) is reported as one ``ValueError`` with a
readable message, so importers need a single except clause.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

__all__ = ["DEFAULT_MAX_JSON_BYTES", "parse_json_bytes", "read_bounded_json"]

DEFAULT_MAX_JSON_BYTES = 64 * 1024 * 1024


def parse_json_bytes(raw: bytes, source: object) -> object:
    """Parse JSON bytes, converting decoder and recursion failures to ValueError."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source}: invalid JSON: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ValueError(f"{source}: not valid UTF-8 JSON: {exc}") from exc
    except RecursionError as exc:
        raise ValueError(f"{source}: JSON is nested too deeply") from exc


def read_bounded_json(path: Path, max_bytes: int = DEFAULT_MAX_JSON_BYTES) -> object:
    """Load a JSON document from a regular file of at most ``max_bytes`` bytes."""
    path = Path(path)
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError(f"{path}: not a regular file")
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        raise ValueError(f"{path}: cannot read file: {exc}") from exc
    if len(raw) > max_bytes:
        raise ValueError(f"{path}: file exceeds the {max_bytes} byte limit")
    return parse_json_bytes(raw, path)
