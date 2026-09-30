"""Shared identifier and label helpers for report diagram renderers."""

from __future__ import annotations

import html as html_mod
import re


def sanitize_id(text: str, fallback: str = "node") -> str:
    """Convert arbitrary strings to safe identifiers (alphanumeric + underscore)."""
    if not text:
        return fallback
    return re.sub(r"[^a-zA-Z0-9_]", "_", str(text))


def truncate(text: str, max_len: int = 30) -> str:
    """Truncate long labels for diagram readability."""
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def safe_label(value: object, max_len: int = 30) -> str:
    """Return a bounded, Mermaid-safe label without changing rendered output."""
    label = truncate(str(value), max_len).replace('"', "'")
    return html_mod.escape(label, quote=True)
