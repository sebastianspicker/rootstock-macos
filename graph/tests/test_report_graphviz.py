import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from report_graphviz import generate_dot


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

    assert 'URL="' not in label_line
    assert "\\\\\\" in label_line
    assert "\\n" in label_line
