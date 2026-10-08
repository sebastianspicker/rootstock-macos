"""Generate a private, offline investigation without Neo4j or active probing."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

from ..models import ScanResult
from ..vulnerability.cve_enrichment_cache import read_json_object
from ..vulnerability.nvd_installed import MAX_SCAN_JSON_BYTES
from .assemble import investigate
from .render import render_html, render_text


def load_artifact(path: Path) -> tuple[ScanResult, dict]:
    raw = read_json_object(path, MAX_SCAN_JSON_BYTES)
    scan = ScanResult.model_validate(raw)
    # Hash the exact parsed content rather than rereading a potentially changing file.
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    normalized = json.dumps(
        scan.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return scan, {
        "path": str(path),
        "canonical_json_sha256": hashlib.sha256(encoded).hexdigest(),
        "normalized_scan_sha256": hashlib.sha256(normalized).hexdigest(),
        "hash_encoding": "UTF-8, sorted keys, compact separators, ensure_ascii=true",
    }


def write_private(path: Path, payload: str) -> None:
    """Owner-only atomic output; never truncate a destination or follow its symlink."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=".investigation-", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan", type=Path, help="Collector scan JSON")
    parser.add_argument("--baseline", type=Path, help="Earlier scan of the same host")
    parser.add_argument("--format", choices=("text", "json", "html"), default="text")
    parser.add_argument("--output", "-o", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.output and args.output.resolve() in {
            path.resolve() for path in (args.scan, args.baseline) if path
        }:
            raise ValueError("Output must not overwrite a source scan")
        scan, source = load_artifact(args.scan)
        baseline, baseline_source = load_artifact(args.baseline) if args.baseline else (None, None)
        report = investigate(scan, baseline)
        report["source_artifacts"] = [source] + ([baseline_source] if baseline_source else [])
        if args.format == "json":
            output = json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        elif args.format == "html":
            output = render_html(report)
        else:
            output = render_text(report)
        if args.output:
            write_private(args.output, output)
            print(f"Investigation written to {args.output}", file=sys.stderr)
        else:
            print(output, end="")
    except (ValueError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
