#!/usr/bin/env python3
import json
import sys
from pathlib import Path

import atheris

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "graph"))

from models import ScanResult  # noqa: E402


def TestOneInput(data: bytes) -> None:
    try:
        decoded = data.decode("utf-8")
        candidate = json.loads(decoded)
        ScanResult.model_validate(candidate)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
