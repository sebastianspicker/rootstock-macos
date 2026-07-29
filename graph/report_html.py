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
      --ink: #061521;
      --ink-deep: #03101a;
      --pane: #091b28;
      --pane-raised: #0d2231;
      --rule: #294353;
      --rule-strong: #3f5b6b;
      --text: #f3f6f7;
      --muted: #a9b7c3;
      --subtle: #7f93a2;
      --action: #3988ff;
      --critical: #ff625a;
      --high: #ff984b;
      --medium: #f5c84d;
      --verified: #6fc981;
      --font-ui: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
      --font-mono: "SF Mono", Menlo, Consolas, monospace;
    }}
    * {{ box-sizing: border-box; }}
    html {{ background: var(--ink); }}
    body {{
      max-width: 1240px;
      margin: 0 auto;
      padding: 0 32px 56px;
      background: var(--ink);
      color: var(--text);
      font: 15px/1.65 var(--font-ui);
      -webkit-font-smoothing: antialiased;
    }}
    a {{ color: var(--action); text-underline-offset: 3px; }}
    a:hover {{ text-decoration-thickness: 2px; }}
    a:focus-visible, [tabindex]:focus-visible {{
      outline: 2px solid var(--action);
      outline-offset: 3px;
    }}
    .report-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      min-height: 58px;
      margin-bottom: 48px;
      border-bottom: 1px solid var(--rule);
    }}
    .report-mark {{
      display: grid;
      place-items: center;
      width: 28px;
      height: 28px;
      border: 1px solid var(--text);
      border-radius: 2px;
      font: 600 13px var(--font-mono);
    }}
    .report-brand {{
      font: 700 12px var(--font-mono);
      letter-spacing: .22em;
    }}
    .report-kind {{
      margin-left: auto;
      color: var(--muted);
      font: 10px var(--font-mono);
      letter-spacing: .08em;
      text-transform: uppercase;
    }}
    #report-content {{ max-width: 980px; margin: 0 auto; }}
    h1 {{
      max-width: 24ch;
      margin: 0 0 28px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--rule-strong);
      color: var(--text);
      font-size: clamp(2rem, 5vw, 3.4rem);
      font-weight: 620;
      line-height: 1.06;
      letter-spacing: -.035em;
    }}
    h2 {{
      margin: 3.2em 0 1em;
      padding: 0 0 10px;
      border-bottom: 1px solid var(--rule);
      color: var(--text);
      font-size: 1.25rem;
      font-weight: 620;
      line-height: 1.2;
    }}
    h3 {{
      margin: 2em 0 .65em;
      color: var(--action);
      font-size: 1rem;
      font-weight: 650;
    }}
    h4 {{
      margin: 1.4em 0 .5em;
      color: var(--muted);
      font-size: .85rem;
      font-weight: 650;
      letter-spacing: .04em;
      text-transform: uppercase;
    }}
    p {{ margin: .8em 0; color: var(--text); }}
    em {{ color: var(--muted); }}
    .table-scroll {{
      margin: 1.2em 0;
      overflow-x: auto;
      border: 1px solid var(--rule);
      scrollbar-color: var(--rule-strong) transparent;
    }}
    figure {{ margin: 0; }}
    figcaption {{
      padding: 9px 12px;
      border-bottom: 1px solid var(--rule);
      color: var(--muted);
      font: 10px var(--font-mono);
      letter-spacing: .05em;
      text-transform: uppercase;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      min-width: 560px;
      font-size: .86rem;
    }}
    th, td {{
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--rule);
      vertical-align: top;
    }}
    th {{
      background: var(--ink-deep);
      color: var(--muted);
      font: 650 10px var(--font-mono);
      letter-spacing: .04em;
      text-transform: uppercase;
    }}
    tr:last-child td {{ border-bottom: 0; }}
    tr:hover td {{ background: var(--pane); }}
    blockquote {{
      margin: 1.2em 0;
      padding: 12px 16px;
      border: 1px solid var(--rule);
      border-left: 3px solid var(--high);
      background: var(--ink-deep);
      color: var(--muted);
      font-size: .92rem;
    }}
    blockquote strong {{ color: var(--high); }}
    code {{
      border: 1px solid var(--rule);
      border-radius: 3px;
      background: var(--ink-deep);
      padding: 2px 6px;
      color: var(--action);
      font: .84em var(--font-mono);
    }}
    pre {{
      padding: 16px;
      overflow-x: auto;
      border: 1px solid var(--rule);
      background: var(--ink-deep);
      font-size: .84rem;
    }}
    pre code {{
      border: 0;
      padding: 16px;
      padding: 0;
      background: transparent;
    }}
    ul, ol {{ padding-left: 24px; margin: 0.8em 0; }}
    li {{ margin: .42em 0; color: var(--text); line-height: 1.5; }}
    li::marker {{ color: var(--subtle); }}
    strong {{ color: var(--text); }}
    .tier-0 {{ color: var(--critical); font-weight: 700; }}
    .tier-1 {{ color: var(--high); font-weight: 700; }}
    .tier-2 {{ color: var(--action); font-weight: 600; }}
    .mermaid {{ margin: 1.5em 0; }}
    @media (prefers-color-scheme: light) {{
      :root {{
        color-scheme: light;
        --ink: #eef4f8;
        --ink-deep: #f7fafc;
        --pane: #ffffff;
        --pane-raised: #e7eff5;
        --rule: #b8c8d4;
        --rule-strong: #8da3b2;
        --text: #102331;
        --muted: #445d6f;
        --subtle: #5f7585;
        --action: #075dc9;
        --critical: #b72d32;
        --high: #9a4d00;
        --medium: #735c00;
        --verified: #116c3a;
      }}
    }}
    .report-footer {{
      max-width: 980px;
      margin: 56px auto 0;
      padding-top: 16px;
      border-top: 1px solid var(--rule);
      color: var(--subtle);
      font: 10px var(--font-mono);
    }}
    @media (max-width: 640px) {{
      body {{ padding-inline: 16px; }}
      .report-header {{ margin-bottom: 32px; }}
      .report-kind {{ display: none; }}
      h1 {{ font-size: 2.15rem; }}
      dl {{ grid-template-columns: 1fr; }}
    }}
    @media (prefers-reduced-motion: reduce) {{
      *, *::before, *::after {{
        scroll-behavior: auto !important;
        transition-duration: .001ms !important;
      }}
    }}
    @media print {{
      :root {{
        --ink: #fff;
        --ink-deep: #fff;
        --pane: #fff;
        --rule: #c8c8c8;
        --rule-strong: #777;
        --text: #111;
        --muted: #333;
        --subtle: #555;
        --action: #134f9b;
      }}
      body {{ max-width: none; padding: 0; }}
      .report-header {{ min-height: 42px; margin-bottom: 28px; }}
      .table-scroll {{ overflow: visible; }}
      a {{ color: #111; text-decoration: underline; }}
    }}
  </style>
</head>
<body>
<header class="report-header">
  <span class="report-mark" aria-hidden="true">R</span>
  <span class="report-brand">ROOTSTOCK</span>
  <span class="report-kind">Security assessment / verified output</span>
</header>
<main id="report-content">
{body}
</main>
<footer class="report-footer">
  Generated by Rootstock · macOS attack-path discovery
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
