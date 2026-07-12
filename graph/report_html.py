"""HTML conversion for Rootstock Markdown reports."""

from __future__ import annotations

REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rootstock Security Assessment Report</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg-primary: #0b1016;
      --bg-secondary: #131a22;
      --bg-tertiary: #1b2430;
      --border: #344253;
      --text-primary: #f3f6f9;
      --text-secondary: #aeb8c4;
      --text-muted: #8c99a8;
      --accent-blue: #6aafff;
      --accent-red: #ff6b72;
      --accent-orange: #f2b84b;
      --accent-green: #59c77a;
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
      border-bottom: 1px solid var(--border);
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
      background: #e05260;
      border-radius: 8px;
      font-size: 20px;
      font-weight: 700;
      color: #fff;
      flex-shrink: 0;
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
    .table-scroll {{ overflow-x: auto; margin: 1em 0; }}
    figure {{ margin: 0; }}
    figcaption {{ color: var(--text-secondary); font-size: 0.85em; margin-bottom: 0.5em; }}
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
    }}
    tr:nth-child(even) {{ background: rgba(22,27,34,.5); }}
    tr:hover {{ background: rgba(88,166,255,.06); }}
    td {{ color: var(--text-primary); }}

    /* Blockquotes (risk callouts) */
    blockquote {{
      background: var(--bg-secondary);
      border: 1px solid var(--accent-orange);
      padding: 14px 18px;
      margin: 1.2em 0;
      border-radius: 8px;
      color: var(--text-secondary);
      font-size: 0.92em;
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
      blockquote {{ background: #fff8e1; border-color: #8a5a00; color: #333; }}
      code {{ background: #f4f4f4; color: #c62828; border-color: #ddd; }}
      pre {{ background: #f4f4f4; border-color: #ddd; }}
      .table-scroll {{ overflow: visible; }}
      a {{ color: #111; text-decoration: underline; }}
    }}

    @media (prefers-color-scheme: light) {{
      :root {{
        color-scheme: light;
        --bg-primary: #f4f7fa;
        --bg-secondary: #ffffff;
        --bg-tertiary: #eaf0f5;
        --border: #c4ced8;
        --text-primary: #17212b;
        --text-secondary: #526273;
        --text-muted: #526273;
        --accent-blue: #0a61c9;
        --accent-red: #bd2432;
        --accent-orange: #8a5a00;
        --accent-green: #116b36;
      }}
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
<header class="report-header">
  <p>Security assessment</p>
</header>
<main id="report-content">
{body}
</main>
<footer class="report-footer">
  Generated by Rootstock &mdash; macOS Attack Path Discovery
</footer>
</body>
</html>"""


def _responsive_tables(body: str) -> str:
    """Give Markdown tables a caption and a horizontal-scroll container."""
    return body.replace(
        "<table>",
        '<div class="table-scroll" role="region" aria-label="Scrollable report data table" '
        'tabindex="0"><figure><figcaption>Report data table</figcaption><table>',
    ).replace("</table>", "</table></figure></div>")


def markdown_to_html(md: str) -> str:
    """Convert a Markdown report to accessible HTML using the required renderer."""
    try:
        import markdown as md_lib

    except ImportError as exc:
        raise RuntimeError(
            "HTML report rendering requires Markdown>=3.8.1,<4; install graph dependencies."
        ) from exc

    body = md_lib.markdown(md, extensions=["tables", "fenced_code", "sane_lists"])
    body = _responsive_tables(body)

    return REPORT_HTML_TEMPLATE.format(body=body)
