#!/usr/bin/env python3
"""Keep the checked-in Blue event taxonomy aligned with its Swift constants."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SWIFT = ROOT / "rootstock-blue/Sources/RootstockBlueCore/FieldTaxonomy.swift"
YAML = ROOT / "rootstock-blue/Content/field-taxonomy/macos-events.yaml"


def main() -> int:
    swift_source = SWIFT.read_text(encoding="utf-8").split("public enum EventVocabulary", 1)[0]
    swift_fields = set(re.findall(r'public static let \w+ = "([a-z][a-z0-9_.]+)"', swift_source))
    yaml_fields = set(
        re.findall(r"^  ([a-z][a-z0-9_.]+):", YAML.read_text(encoding="utf-8"), re.MULTILINE)
    )
    missing_from_yaml = sorted(swift_fields - yaml_fields)
    missing_from_swift = sorted(yaml_fields - swift_fields)
    if missing_from_yaml or missing_from_swift:
        if missing_from_yaml:
            print(
                f"FAIL taxonomy fields missing from YAML: {', '.join(missing_from_yaml)}",
                file=sys.stderr,
            )
        if missing_from_swift:
            print(
                f"FAIL taxonomy fields missing from Swift: {', '.join(missing_from_swift)}",
                file=sys.stderr,
            )
        return 1
    print(f"Blue field taxonomy parity OK: {len(swift_fields)} fields")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
