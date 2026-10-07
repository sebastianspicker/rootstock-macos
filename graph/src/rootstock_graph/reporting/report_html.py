"""HTML conversion for Rootstock Markdown reports."""

from __future__ import annotations

import html
from html.parser import HTMLParser

REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
  <title>Rootstock Security Assessment Report</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #f4f6f9;
      --ink-deep: #ffffff;
      --pane: #ffffff;
      --pane-raised: #eef1f5;
      --pane-selected: #e1ebfb;
      --hover: rgba(15, 23, 42, 0.05);
      --text: #0f172a;
      --muted: #475569;
      --subtle: #5b6678;
      --rule: #dde3ea;
      --rule-strong: #768396;
      --action: #0b5cd5;
      --link: #0b5cd5;
      --focus-ring: #0b5cd5;
      --annotation: #6d28d9;
      --gap: #8a5a00;
      --gap-rule: #b07d00;
      --gap-dim: rgba(217, 154, 0, 0.12);
      --critical: #b4123a;
      --high: #c2410c;
      --medium: #8f6a00;
      --low: #0e7490;
      --info: #5b6678;
      --verified: #15803d;
      --on-severity: #ffffff;
      --radius: 4px;
      --font-ui: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, "Helvetica Neue", Arial, sans-serif;
      --font-mono: "SF Mono", "JetBrains Mono", ui-monospace, Menlo, Consolas, "Liberation Mono", monospace;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        color-scheme: dark;
        --ink: #0d1117;
        --ink-deep: #090c10;
        --pane: #131820;
        --pane-raised: #1a212b;
        --pane-selected: #1c2b45;
        --hover: rgba(148, 163, 184, 0.08);
        --text: #e6edf3;
        --muted: #a6b1bd;
        --subtle: #8a96a3;
        --rule: #262e39;
        --rule-strong: #6a7686;
        --action: #1d6ae5;
        --link: #4d94ff;
        --focus-ring: #4d94ff;
        --annotation: #b392f0;
        --gap: #e3b341;
        --gap-rule: #9e7a1e;
        --gap-dim: rgba(227, 179, 65, 0.10);
        --critical: #ff5c7c;
        --high: #ff8f4d;
        --medium: #e8c547;
        --low: #4fc3d9;
        --info: #8a96a3;
        --verified: #56d364;
        --on-severity: #0d1117;
      }}
    }}
    * {{ box-sizing: border-box; }}
    html {{ background: var(--ink); }}
    body {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 24px 48px;
      background: var(--ink);
      color: var(--text);
      font: 14px/1.55 var(--font-ui);
      -webkit-font-smoothing: antialiased;
    }}
    a {{ color: var(--link); text-underline-offset: 2px; }}
    a:focus-visible, [tabindex]:focus-visible {{
      outline: 2px solid var(--focus-ring);
      outline-offset: 1px;
    }}
    .report-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      height: 48px;
      margin: 0 -24px 24px;
      padding: 0 24px;
      background: var(--pane);
      border-bottom: 1px solid var(--rule);
    }}
    .report-mark {{
      display: grid;
      place-items: center;
      width: 22px;
      height: 22px;
      border-radius: var(--radius);
      background: var(--text);
      color: var(--ink);
      font: 700 13px var(--font-mono);
    }}
    .report-brand {{ font: 600 14px var(--font-ui); }}
    .report-kind {{
      display: inline-flex;
      align-items: center;
      height: 20px;
      margin-left: auto;
      padding: 0 8px;
      border: 1px solid var(--rule-strong);
      border-radius: var(--radius);
      color: var(--muted);
      font: 600 11px var(--font-ui);
      letter-spacing: .06em;
      text-transform: uppercase;
    }}
    #report-content {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{
      margin: 0 0 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--rule-strong);
      font-size: 24px;
      font-weight: 600;
      line-height: 1.25;
    }}
    h2 {{
      margin: 32px 0 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--rule);
      font-size: 16px;
      font-weight: 600;
      line-height: 1.3;
    }}
    h3 {{
      margin: 20px 0 8px;
      color: var(--text);
      font-size: 14px;
      font-weight: 600;
    }}
    h4 {{
      margin: 16px 0 8px;
      color: var(--subtle);
      font-size: 11px;
      font-weight: 600;
      letter-spacing: .06em;
      text-transform: uppercase;
    }}
    p {{ margin: 8px 0; }}
    em {{ color: var(--muted); }}
    .table-scroll {{
      margin: 12px 0;
      overflow-x: auto;
      border: 1px solid var(--rule);
      border-radius: var(--radius);
      background: var(--ink-deep);
      scrollbar-color: var(--rule-strong) transparent;
    }}
    figure {{ margin: 0; }}
    figcaption {{
      padding: 8px 12px;
      border-bottom: 1px solid var(--rule);
      background: var(--pane-raised);
      color: var(--subtle);
      font: 600 11px var(--font-ui);
      letter-spacing: .06em;
      text-transform: uppercase;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      min-width: 560px;
      font-size: 13px;
      font-variant-numeric: tabular-nums;
    }}
    th, td {{
      padding: 7px 12px;
      text-align: left;
      border-bottom: 1px solid var(--rule);
      vertical-align: top;
    }}
    th {{
      background: var(--pane-raised);
      color: var(--subtle);
      font: 600 11px var(--font-ui);
      letter-spacing: .06em;
      text-transform: uppercase;
    }}
    tr:last-child td {{ border-bottom: 0; }}
    tr:hover td {{ background: var(--hover); }}
    blockquote {{
      margin: 12px 0;
      padding: 8px 12px;
      border-left: 3px solid var(--gap-rule);
      background: var(--gap-dim);
      color: var(--text);
    }}
    blockquote p {{ margin: 4px 0; }}
    blockquote strong {{ color: var(--gap); }}
    code {{
      border: 1px solid var(--rule);
      border-radius: 3px;
      background: var(--pane-raised);
      padding: 1px 5px;
      color: var(--text);
      font: 12px var(--font-mono);
    }}
    pre {{
      padding: 12px;
      overflow-x: auto;
      border: 1px solid var(--rule);
      border-radius: var(--radius);
      background: var(--ink-deep);
      font-size: 12px;
    }}
    pre code {{ border: 0; padding: 0; background: transparent; }}
    td code {{ border: 0; padding: 0; background: transparent; }}
    ul, ol {{ padding-left: 24px; margin: 8px 0; }}
    li {{ margin: 4px 0; }}
    li::marker {{ color: var(--subtle); }}
    strong {{ color: var(--text); }}
    .tier-0, .tier-1, .tier-2 {{
      display: inline-block;
      padding: 1px 6px;
      border-radius: 3px;
      color: var(--on-severity);
      font: 700 11px var(--font-ui);
      text-transform: uppercase;
    }}
    .tier-0 {{ background: var(--critical); }}
    .tier-1 {{ background: var(--high); }}
    .tier-2 {{ background: var(--medium); }}
    .mermaid {{ margin: 16px 0; }}
    .report-footer {{
      margin: 40px 0 0;
      padding-top: 12px;
      border-top: 1px solid var(--rule);
      color: var(--subtle);
      font: 11px var(--font-mono);
    }}
    @media (max-width: 640px) {{
      body {{ padding-inline: 16px; }}
      .report-header {{ margin-inline: -16px; padding-inline: 16px; }}
      .report-kind {{ display: none; }}
    }}
    @media (prefers-reduced-motion: reduce) {{
      *, *::before, *::after {{
        scroll-behavior: auto !important;
        transition-duration: .001ms !important;
      }}
    }}
    @media print {{
      :root {{
        color-scheme: light;
        --ink: #fff;
        --ink-deep: #fff;
        --pane: #fff;
        --pane-raised: #f0f0f0;
        --hover: transparent;
        --rule: #c8c8c8;
        --rule-strong: #777;
        --text: #000;
        --muted: #222;
        --subtle: #444;
        --action: #134f9b;
        --gap: #5c3c00;
        --gap-dim: #fdf3d8;
        --critical: #b4123a;
        --high: #c2410c;
        --medium: #8f6a00;
        --on-severity: #fff;
      }}
      * {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      body {{ max-width: none; padding: 0; }}
      .report-header {{ margin: 0 0 16px; padding: 0; }}
      .table-scroll {{ overflow: visible; }}
      a {{ color: #000; text-decoration: underline; }}
    }}
  </style>
</head>
<body>
<header class="report-header">
  <span class="report-mark" aria-hidden="true">R</span>
  <span class="report-brand">Rootstock</span>
  <span class="report-kind">Security assessment / generated local output</span>
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


_SAFE_REPORT_TAGS = {
    "p",
    "h1",
    "h2",
    "h3",
    "h4",
    "ul",
    "ol",
    "li",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "pre",
    "code",
    "em",
    "strong",
    "blockquote",
    "a",
    "br",
    "hr",
}
_DROP_REPORT_CONTENT_TAGS = {
    "script",
    "style",
    "iframe",
    "object",
    "embed",
    "svg",
    "math",
    "form",
    "template",
}


class _InertReportHTML(HTMLParser):
    """Retain Markdown structure while removing every active-content surface."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.output: list[str] = []
        self._dropped_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        tag = tag.lower()
        if tag in _DROP_REPORT_CONTENT_TAGS:
            self._dropped_depth += 1
            return
        if self._dropped_depth or tag == "img" or tag not in _SAFE_REPORT_TAGS:
            return
        # Links intentionally keep their readable text but no href. Report
        # evidence is untrusted and must never become a navigation surface.
        self.output.append(f"<{tag}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        tag = tag.lower()
        if not self._dropped_depth and tag in {"br", "hr"}:
            self.output.append(f"<{tag}>")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in _DROP_REPORT_CONTENT_TAGS:
            if self._dropped_depth:
                self._dropped_depth -= 1
            return
        if not self._dropped_depth and tag in _SAFE_REPORT_TAGS and tag not in {"br", "hr"}:
            self.output.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if not self._dropped_depth:
            self.output.append(html.escape(data, quote=False))

    def handle_entityref(self, name: str) -> None:
        if not self._dropped_depth:
            self.output.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        if not self._dropped_depth:
            self.output.append(f"&#{name};")


def _inert_report_html(body: str) -> str:
    parser = _InertReportHTML()
    parser.feed(body)
    parser.close()
    return "".join(parser.output)


def markdown_to_html(md: str) -> str:
    """Convert a Markdown report to accessible HTML using the required renderer."""
    try:
        import markdown as md_lib

    except ImportError as exc:
        raise RuntimeError(
            "HTML report rendering requires Markdown>=3.8.1,<4; install graph dependencies."
        ) from exc

    body = md_lib.markdown(md, extensions=["tables", "fenced_code", "sane_lists"])
    body = _inert_report_html(body)
    body = _responsive_tables(body)

    return REPORT_HTML_TEMPLATE.format(body=body)
