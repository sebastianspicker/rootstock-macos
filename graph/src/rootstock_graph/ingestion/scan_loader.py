"""scan_loader.py - Load and validate Rootstock scan JSON files."""

from __future__ import annotations

import sys
from pathlib import Path

from pydantic import ValidationError

from ..models import ScanResult
from .bounded_json import read_bounded_json


def load_scan(path: Path) -> ScanResult | None:
    """Load and validate a scan JSON file. Returns None on fatal error."""
    try:
        data = read_bounded_json(path)
    except ValueError as e:
        print(f"ERROR: Cannot read {path}: {e}", file=sys.stderr)
        return None

    try:
        return ScanResult.model_validate(data)
    except ValidationError as e:
        print(f"ERROR: Scan JSON failed schema validation:\n{e}", file=sys.stderr)
        return None
