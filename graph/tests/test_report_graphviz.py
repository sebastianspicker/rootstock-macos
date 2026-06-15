import sys
from unittest import TestCase
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from report_graphviz import generate_dot, render_dot


checks = TestCase()


def test_generate_dot_escapes_backslash_quote_and_newline_in_labels():
    dot = generate_dot(
        [
            {
                "id": "1",
                "label": "Application",
                "display": 'evil\\"] URL="javascript:alert(1)\nnext',
                "bundle_id": "",
            }
        ],
        [],
    )

    label_line = next(line for line in dot.splitlines() if "label=" in line)

    checks.assertNotIn('URL="', label_line)
    checks.assertIn("\\\\\\", label_line)
    checks.assertIn("\\n", label_line)


def test_render_dot_rejects_automatic_graphviz_execution(tmp_path):
    dot_file = tmp_path / "evil;touch owned.dot"
    dot_file.write_text("digraph rootstock {}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Automatic Graphviz rendering is disabled"):
        render_dot(dot_file, "svg")


def test_render_dot_rejects_unsupported_output_format(tmp_path):
    dot_file = tmp_path / "graph.dot"
    dot_file.write_text("digraph rootstock {}", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported Graphviz output format"):
        render_dot(dot_file, "png;touch owned")
