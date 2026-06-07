"""HTML conversion for Rootstock Markdown reports."""

from __future__ import annotations

import html as html_mod


REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rootstock Security Assessment Report</title>
  <style>
    :root {{
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #1c2333;
      --border: #30363d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --text-muted: #484f58;
      --accent-blue: #58a6ff;
      --accent-red: #f85149;
      --accent-orange: #d29922;
      --accent-green: #3fb950;
      --accent-purple: #bc8cff;
      --severity-critical: #f85149;
      --severity-high: #d29922;
      --severity-medium: #58a6ff;
      --severity-low: #3fb950;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
      max-width: 1200px; margin: 0 auto; padding: 40px 24px;
      background: var(--bg-primary); color: var(--text-primary);
      line-height: 1.6;
    }}
    a {{ color: var(--accent-blue); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}

    /* Header */
    h1 {{
      color: var(--text-primary);
      font-size: 1.8em;
      font-weight: 700;
      padding-bottom: 12px;
      margin-bottom: 8px;
      border-bottom: 3px solid var(--accent-red);
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    h1::before {{
      content: "R";
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 36px; height: 36px;
      background: linear-gradient(135deg, #e63946, #d62828);
      border-radius: 8px;
      font-size: 20px;
      font-weight: 700;
      color: #fff;
      flex-shrink: 0;
      box-shadow: 0 2px 8px rgba(230,57,70,.3);
    }}
    h2 {{
      color: var(--text-primary);
      font-size: 1.3em;
      font-weight: 600;
      padding: 10px 0 8px 0;
      margin-top: 2.5em;
      margin-bottom: 0.8em;
      border-bottom: 1px solid var(--border);
      position: relative;
    }}
    /* Severity-coded section borders */
    h2:has(+ blockquote) {{
      padding-left: 14px;
    }}
    h3 {{
      color: var(--accent-blue);
      font-size: 1.05em;
      font-weight: 600;
      margin-top: 1.8em;
      margin-bottom: 0.6em;
    }}
    h4 {{
      color: var(--text-secondary);
      font-size: 0.95em;
      font-weight: 600;
      margin-top: 1.2em;
      margin-bottom: 0.5em;
    }}
    p {{ margin: 0.8em 0; color: var(--text-primary); }}
    em {{ color: var(--text-secondary); }}

    /* Tables */
    table {{
      border-collapse: collapse;
      width: 100%;
      margin: 1em 0;
      font-size: 0.88em;
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid var(--border);
    }}
    th, td {{
      padding: 10px 14px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      background: var(--bg-tertiary);
      color: var(--text-secondary);
      font-weight: 600;
      font-size: 0.85em;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    tr:nth-child(even) {{ background: rgba(22,27,34,.5); }}
    tr:hover {{ background: rgba(88,166,255,.06); }}
    td {{ color: var(--text-primary); }}

    /* Blockquotes (risk callouts) */
    blockquote {{
      background: var(--bg-secondary);
      border-left: 4px solid var(--accent-orange);
      padding: 14px 18px;
      margin: 1.2em 0;
      border-radius: 0 8px 8px 0;
      color: var(--text-secondary);
      font-size: 0.92em;
      backdrop-filter: blur(4px);
    }}
    blockquote strong {{ color: var(--accent-orange); }}

    /* Code */
    code {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.88em;
      font-family: "SF Mono", Menlo, "Fira Code", monospace;
      color: var(--accent-blue);
    }}
    pre {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      padding: 16px;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 0.88em;
    }}
    pre code {{
      border: none;
      padding: 0;
      background: transparent;
    }}

    /* Lists */
    ul, ol {{ padding-left: 24px; margin: 0.8em 0; }}
    li {{
      margin: 0.4em 0;
      color: var(--text-primary);
      line-height: 1.5;
    }}
    li::marker {{ color: var(--text-muted); }}

    /* Severity badges via text patterns */
    strong {{ color: var(--text-primary); }}

    /* Tier badges */
    .tier-0 {{ color: var(--severity-critical); font-weight: 700; }}
    .tier-1 {{ color: var(--severity-high); font-weight: 700; }}
    .tier-2 {{ color: var(--severity-medium); font-weight: 600; }}

    /* Mermaid diagrams */
    .mermaid {{ margin: 1.5em 0; }}

    /* Print styles */
    @media print {{
      body {{ background: #fff; color: #111; max-width: 100%; padding: 20px; }}
      h1 {{ color: #c62828; }}
      h1::before {{ background: #c62828; }}
      h2 {{ color: #333; border-bottom-color: #ddd; }}
      h3 {{ color: #2255aa; }}
      table {{ border-color: #ddd; }}
      th {{ background: #f4f4f4; color: #333; }}
      tr:nth-child(even) {{ background: #fafafa; }}
      blockquote {{ background: #fff8e1; border-left-color: #ffc107; color: #555; }}
      code {{ background: #f4f4f4; color: #c62828; border-color: #ddd; }}
      pre {{ background: #f4f4f4; border-color: #ddd; }}
    }}

    /* Footer */
    .report-footer {{
      margin-top: 3em;
      padding-top: 1.5em;
      border-top: 1px solid var(--border);
      font-size: 0.85em;
      color: var(--text-muted);
      text-align: center;
    }}
  </style>
</head>
<body>
{body}
<div class="report-footer">
  Generated by Rootstock &mdash; macOS Attack Path Discovery
</div>
</body>
</html>"""


def _close_fallback_list(lines: list[str], in_list: bool) -> bool:
    if in_list:
        lines.append("</ul>")
    return False


def _append_fallback_markdown_line(
    lines: list[str],
    line: str,
    in_list: bool,
) -> bool:
    if line.startswith("# "):
        in_list = _close_fallback_list(lines, in_list)
        lines.append(f"<h1>{html_mod.escape(line[2:])}</h1>")
    elif line.startswith("## "):
        in_list = _close_fallback_list(lines, in_list)
        lines.append(f"<h2>{html_mod.escape(line[3:])}</h2>")
    elif line.startswith("### "):
        in_list = _close_fallback_list(lines, in_list)
        lines.append(f"<h3>{html_mod.escape(line[4:])}</h3>")
    elif line.startswith("- "):
        if not in_list:
            lines.append("<ul>")
            in_list = True
        lines.append(f"<li>{html_mod.escape(line[2:])}</li>")
    elif line.strip():
        in_list = _close_fallback_list(lines, in_list)
        lines.append(f"<p>{html_mod.escape(line)}</p>")
    return in_list


def _fallback_markdown_to_html_body(md: str) -> str:
    lines: list[str] = []
    in_list = False
    for line in md.split("\n"):
        in_list = _append_fallback_markdown_line(lines, line, in_list)
    _close_fallback_list(lines, in_list)
    return "\n".join(lines)


def markdown_to_html(md: str) -> str:
    """Convert Markdown report to HTML. Uses `markdown` package if available."""
    try:
        import markdown as md_lib

        body = md_lib.markdown(md, extensions=["tables", "fenced_code"])
    except ImportError:
        # Minimal fallback preserves readability without the markdown package.
        body = _fallback_markdown_to_html_body(md)

    return REPORT_HTML_TEMPLATE.format(body=body)
