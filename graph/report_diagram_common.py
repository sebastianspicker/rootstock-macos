"""Shared escaping helpers for report diagram renderers."""

from __future__ import annotations

import html as html_mod

from utils import truncate as _truncate


def safe_label(value: object, max_len: int = 30) -> str:
    """Return a bounded, Mermaid-safe label without changing rendered output."""
    label = _truncate(str(value), max_len).replace('"', "'")
    return html_mod.escape(label, quote=True)
