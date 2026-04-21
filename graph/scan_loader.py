"""scan_loader.py — Load and validate Rootstock scan JSON files."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import ValidationError

from models import ScanResult


def load_scan(path: Path) -> ScanResult | None:
    """Load and validate a scan JSON file. Returns None on fatal error."""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"ERROR: Cannot read {path}: {e}", file=sys.stderr)
        return None

    try:
        return ScanResult.model_validate(data)
    except ValidationError as e:
        print(f"ERROR: Scan JSON failed schema validation:\n{e}", file=sys.stderr)
        return None
