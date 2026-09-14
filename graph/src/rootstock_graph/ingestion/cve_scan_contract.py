"""Packaged schema loading for the cve-scan export contract."""

from __future__ import annotations

import json
from importlib.resources import files

from jsonschema import Draft202012Validator, FormatChecker


def load_schema_validator(schema_id: str) -> Draft202012Validator:
    """Load the packaged v7 schema and reject a mismatched resource identity."""
    schema_path = files("rootstock_graph").joinpath(
        "resources", "contracts", "cve-scan-export", "v7", "schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    if schema.get("$id") != schema_id:
        raise RuntimeError("packaged cve-scan export schema has an unexpected identity")
    return Draft202012Validator(schema, format_checker=FormatChecker(("date-time",)))
