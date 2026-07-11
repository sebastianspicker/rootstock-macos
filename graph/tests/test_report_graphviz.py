from unittest import TestCase

from report_graphviz import generate_dot




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
