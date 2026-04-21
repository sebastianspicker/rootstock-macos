#!/usr/bin/env python3
"""Generate 9 screenshots for the Rootstock README using Playwright."""

from __future__ import annotations

import argparse
import html as html_mod
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
GRAPH_DIR = ROOT / "graph"
sys.path.insert(0, str(GRAPH_DIR))

from generate_mock_graph import build_mock_graph  # noqa: E402


def generate_viewer_html(graph_data: dict) -> str:
    """Embed graph data into viewer_template.html with headless layout fix."""
    template = (GRAPH_DIR / "viewer_template.html").read_text()
    hostname = graph_data.get("metadata", {}).get("hostname", "Demo")
    title = f"{hostname} Attack Graph"
    safe_title = html_mod.escape(title)
    safe_json = json.dumps(graph_data).replace("</", "<\\/")
    html = template.replace("{{VIEWER_TITLE}}", safe_title)
    html = html.replace("{{VIEWER_DATA}}", safe_json)

    # Fix layout for headless rendering: force graph-container to fill viewport
    # beside the sidebar, regardless of DOM nesting.
    layout_fix = """<style>
#graph-container {
  position: fixed !important;
  top: 0 !important;
  left: 280px !important;
  right: 0 !important;
  bottom: 0 !important;
  width: auto !important;
  height: auto !important;
}
#inspector.open {
  position: fixed !important;
  top: 0 !important;
  right: 0 !important;
  bottom: 0 !important;
  z-index: 20 !important;
}
</style>"""
    html = html.replace("</head>", layout_fix + "\n</head>")
    return html


def generate_report_html() -> str:
    """Build a mock report HTML with Mermaid diagrams (no Neo4j)."""
    # Build mock query results matching what assemble_report() expects
    query_results = {
        "01-injectable-fda-apps.cypher": [
            {
                "app_name": "iTerm2",
                "bundle_id": "com.googlecode.iterm2",
                "team_id": "H7V7XYVQ7D",
                "injection_methods": ["dyld_insert_via_entitlement", "missing_library_validation"],
            },
        ],
        "02-shortest-path-to-fda.cypher": [
            {
                "node_names": ["Attacker Payload", "iTerm2", "Full Disk Access"],
                "rel_types": ["CAN_INJECT_INTO", "HAS_TCC_GRANT"],
                "path_length": 2,
            },
            {
                "node_names": ["Attacker Payload", "OmniGraffle", "Finder", "Full Disk Access"],
                "rel_types": ["CAN_INJECT_INTO", "CAN_SEND_APPLE_EVENT", "HAS_TCC_GRANT"],
                "path_length": 3,
            },
        ],
        "03-electron-tcc-inheritance.cypher": [
            {
                "app_name": "Slack",
                "bundle_id": "com.tinyspeck.slackmacgap",
                "inherited_permissions": ["Camera", "Microphone", "Screen Recording"],
                "permission_count": 3,
            },
            {
                "app_name": "Visual Studio Code",
                "bundle_id": "com.microsoft.VSCode",
                "inherited_permissions": ["Accessibility"],
                "permission_count": 1,
            },
        ],
        "05-appleevent-tcc-cascade.cypher": [
            {
                "source_app": "OmniGraffle",
                "target_app": "Finder",
                "permission_gained": "Full Disk Access",
            },
        ],
        "07-tcc-grant-overview.cypher": [
            {"permission": "Full Disk Access", "service": "kTCCServiceSystemPolicyAllFiles", "allowed_count": 4, "denied_count": 0, "total_grants": 4},
            {"permission": "Camera", "service": "kTCCServiceCamera", "allowed_count": 3, "denied_count": 0, "total_grants": 3},
            {"permission": "Microphone", "service": "kTCCServiceMicrophone", "allowed_count": 2, "denied_count": 0, "total_grants": 2},
            {"permission": "Accessibility", "service": "kTCCServiceAccessibility", "allowed_count": 3, "denied_count": 0, "total_grants": 3},
            {"permission": "Screen Recording", "service": "kTCCServiceScreenCapture", "allowed_count": 1, "denied_count": 0, "total_grants": 1},
            {"permission": "Automation", "service": "kTCCServiceAppleEvents", "allowed_count": 2, "denied_count": 0, "total_grants": 2},
        ],
        "46-tier-classification.cypher": [
            {"app_name": "iTerm2", "tier": "Tier 0", "risk_score": 95},
            {"app_name": "Acme Backup", "tier": "Tier 0", "risk_score": 80},
            {"app_name": "Slack", "tier": "Tier 1", "risk_score": 72},
            {"app_name": "Visual Studio Code", "tier": "Tier 1", "risk_score": 65},
            {"app_name": "OmniGraffle", "tier": "Tier 1", "risk_score": 60},
            {"app_name": "1Password", "tier": "Tier 1", "risk_score": 58},
            {"app_name": "Zoom", "tier": "Tier 2", "risk_score": 35},
            {"app_name": "Firefox", "tier": "Tier 2", "risk_score": 30},
            {"app_name": "Acme Analytics", "tier": "Tier 2", "risk_score": 25},
            {"app_name": "Acme VPN", "tier": "Tier 2", "risk_score": 20},
            {"app_name": "Finder", "tier": "Tier 2", "risk_score": 15},
            {"app_name": "Terminal", "tier": "Tier 3", "risk_score": 10},
            {"app_name": "System Settings", "tier": "Tier 3", "risk_score": 8},
            {"app_name": "Acme Launcher", "tier": "Tier 3", "risk_score": 5},
        ],
        "95-high-risk-apps.cypher": [
            {"app_name": "iTerm2", "risk_score": 95,
             "attack_categories": ["injectable_fda", "dyld_injection"]},
            {"app_name": "Slack", "risk_score": 72,
             "attack_categories": ["electron_inheritance"]},
        ],
    }

    metadata = {
        "hostname": "acme-macbook-pro",
        "macos_version": "macOS 15.3 (Build 24D60)",
        "timestamp": "2026-03-20T10:00:00Z",
        "scan_id": "demo-0001-acme-macbook-pro",
        "collector_version": "0.1.0",
        "is_root": True,
        "has_fda": True,
        "app_count": 15,
        "tcc_grant_count": 15,
        "entitlement_count": 42,
        "bluetooth_device_count": 3,
        "file_acl_count": 5,
        "login_session_count": 2,
        "icloud_signed_in": True,
        "icloud_drive_enabled": True,
        "icloud_keychain_enabled": True,
    }

    from report_assembly import assemble_report, markdown_to_html
    md = assemble_report(query_results, metadata)
    raw_html = markdown_to_html(md)

    # Inject Mermaid CDN and convert fenced mermaid blocks to <pre class="mermaid">
    mermaid_script = (
        '<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>\n'
        '<script>mermaid.initialize({startOnLoad:true, theme:"default"});</script>\n'
    )
    import re
    raw_html = re.sub(
        r'<pre><code class="language-mermaid">(.*?)</code></pre>',
        lambda m: f'<pre class="mermaid">{m.group(1).strip()}</pre>',
        raw_html, flags=re.DOTALL,
    )
    raw_html = re.sub(
        r'<pre><code>```mermaid\s*(.*?)\s*```</code></pre>',
        lambda m: f'<pre class="mermaid">{m.group(1).strip()}</pre>',
        raw_html, flags=re.DOTALL,
    )
    raw_html = re.sub(
        r'<p>```mermaid\s*</p>\s*(.*?)\s*<p>```</p>',
        lambda m: f'<pre class="mermaid">{m.group(1).strip()}</pre>',
        raw_html, flags=re.DOTALL,
    )

    raw_html = raw_html.replace("</head>", mermaid_script + "</head>")
    return raw_html


def generate_cli_html() -> str:
    """Build a dark-themed terminal mockup showing collector verbose output."""
    modules = [
        ("TCC", "15 grants found", "0.01s", None),
        ("Entitlements", "42 entitlements extracted", "0.15s", None),
        ("CodeSigning", "15 apps analysed", "0.21s", None),
        ("XPC", "5 services enumerated", "4.83s", None),
        ("Persistence", "6 launch items found", "0.01s", None),
        ("Keychain", "4 ACL entries read", "0.06s", None),
        ("MDM", "1 profile found", "0.02s", None),
        ("Groups", "4 groups, 2 users", "0.01s", None),
        ("RemoteAccess", "SSH enabled (port 22)", "0.01s", None),
        ("Firewall", "Enabled, 2 app rules", "0.01s", None),
        ("LoginSession", "2 active sessions", "0.01s", None),
        ("AuthorizationDB", "3 rights analysed", "0.02s", None),
        ("AuthorizationPlugins", "1 plugin found", "0.01s", None),
        ("SystemExtensions", "1 extension found", "0.01s", None),
        ("Sudoers", "1 NOPASSWD rule found", "0.01s", "NOPASSWD"),
        ("ProcessSnapshot", "6 running processes", "0.01s", None),
        ("FileACLs", "5 critical files audited", "0.02s", None),
        ("ShellHooks", ".zshrc writable", "0.01s", "writable"),
        ("PhysicalSecurity", "FileVault: OFF", "0.01s", "OFF"),
        ("ActiveDirectory", "Not bound", "0.01s", None),
        ("KerberosArtifacts", "krb5.conf found", "0.01s", None),
        ("Sandbox", "0 custom profiles", "0.01s", None),
        ("Quarantine", "15 apps checked", "0.02s", None),
    ]

    module_html_lines = []
    for mod_name, desc, timing, warning_word in modules:
        mod_cell = f"[{mod_name}]".ljust(25)
        desc_cell = desc.ljust(28)
        if warning_word and warning_word in desc_cell:
            desc_cell = desc_cell.replace(
                warning_word,
                f'<span class="warning">{warning_word}</span>'
            )
        line = (
            f'  {html_mod.escape(mod_cell)}'
            f'<span class="check">\u2713</span>  '
            f'{desc_cell}'
            f'<span class="timing">{html_mod.escape(timing)}</span>'
        )
        module_html_lines.append(line)

    # Build full content
    content_parts = [
        '<span class="prompt">$ sudo .build/release/rootstock-collector --output scan.json --verbose</span>',
        '',
        '<span class="header">Rootstock Collector v0.1.0</span>',
        '<span class="header">macOS 15.3 (Build 24D60) | Elevation: root + FDA</span>',
        '<span class="separator">' + '\u2500' * 49 + '</span>',
        '',
    ]
    content_parts.extend(module_html_lines)
    content_parts.extend([
        '',
        '<span class="separator">' + '\u2500' * 49 + '</span>',
        '<span class="summary">  Total: 5.49s | 15 apps | 0 errors</span>',
        '<span class="timing">  Output: scan.json (487 KB)</span>',
    ])

    pre_content = "\n".join(content_parts)

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      background: #1e1e1e;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 40px;
    }}
    .terminal {{
      background: #282c34;
      border-radius: 8px;
      width: 780px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.5);
      overflow: hidden;
      font-family: "SF Mono", "Menlo", "Monaco", "Courier New", monospace;
    }}
    .titlebar {{
      background: #21252b;
      padding: 12px 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .dot {{ width: 12px; height: 12px; border-radius: 50%; }}
    .dot-red {{ background: #ff5f57; }}
    .dot-yellow {{ background: #febc2e; }}
    .dot-green {{ background: #28c840; }}
    .titlebar-text {{
      color: #9da5b4;
      font-size: 12px;
      margin-left: 8px;
    }}
    .content {{
      padding: 16px 20px;
      color: #abb2bf;
      font-size: 13px;
      line-height: 1.6;
      white-space: pre;
    }}
    .content .prompt {{ color: #98c379; }}
    .content .check {{ color: #98c379; }}
    .content .timing {{ color: #61afef; }}
    .content .header {{ color: #c678dd; font-weight: bold; }}
    .content .separator {{ color: #4b5263; }}
    .content .warning {{ color: #e5c07b; }}
    .content .summary {{ color: #e06c75; font-weight: bold; }}
  </style>
</head>
<body>
  <div class="terminal">
    <div class="titlebar">
      <div class="dot dot-red"></div>
      <div class="dot dot-yellow"></div>
      <div class="dot dot-green"></div>
      <span class="titlebar-text">rootstock-collector -- zsh -- 80x30</span>
    </div>
    <pre class="content">{pre_content}</pre>
  </div>
</body>
</html>"""


def take_screenshots(
    viewer_html: str,
    report_html: str,
    cli_html: str,
    output_dir: Path,
) -> list[Path]:
    """Use Playwright to capture 9 screenshots."""
    from playwright.sync_api import sync_playwright

    screenshots: list[Path] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
            f.write(viewer_html)
            viewer_path = f.name

        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        page.goto(f"file://{viewer_path}")
        page.wait_for_timeout(500)

        # Trigger canvas resize after CSS layout fix takes effect
        page.evaluate("() => { resizeCanvas(); }")
        page.wait_for_timeout(300)

        # Screenshot 1: Full graph (enable all node types)
        page.evaluate("""() => {
            nodes.forEach(n => activeNodeKinds.add(n.kind));
            computeVisibility();
            markDirty();
            resetZoom();
        }""")
        page.wait_for_timeout(500)
        out1 = output_dir / "01-full-graph.png"
        page.screenshot(path=str(out1))
        screenshots.append(out1)
        print(f"  [1/9] {out1.name}")

        # Screenshot 2: Attack path (attacker -> FDA)
        page.evaluate("""() => {
            const attackerNode = nodes.find(n =>
                n.properties && n.properties.bundle_id === 'attacker.payload');
            const fdaNode = nodes.find(n =>
                n.properties && n.properties.service === 'kTCCServiceSystemPolicyAllFiles');

            if (attackerNode && fdaNode) {
                nodes.forEach(n => activeNodeKinds.add(n.kind));
                pathMode = true;
                pathSource = attackerNode.id;
                pathTarget = fdaNode.id;
                runPathBFS();
                computeVisibility();
                resetZoom();
            }
        }""")
        page.wait_for_timeout(500)
        out2 = output_dir / "02-attack-path.png"
        page.screenshot(path=str(out2))
        screenshots.append(out2)
        print(f"  [2/9] {out2.name}")

        # Screenshot 3: Node inspector (iTerm2)
        page.evaluate("""() => {
            pathMode = false;
            pathResult = null;
            focusNodeId = null;
            nodes.forEach(n => activeNodeKinds.add(n.kind));
            computeVisibility();

            const iterm = nodes.find(n =>
                n.properties && n.properties.bundle_id === 'com.googlecode.iterm2');
            if (iterm) {
                inspectNode(iterm);
                const W = document.getElementById('graph-canvas').width;
                const H = document.getElementById('graph-canvas').height;
                const k = 1.5;
                transform = {
                    x: W/2 - iterm.x * k,
                    y: H/2 - iterm.y * k,
                    k: k
                };
                markDirty();
            }
        }""")
        page.wait_for_timeout(500)
        out3 = output_dir / "03-node-inspector.png"
        page.screenshot(path=str(out3))
        screenshots.append(out3)
        print(f"  [3/9] {out3.name}")

        # Screenshot 4: Electron TCC inheritance (Slack focus mode)
        page.evaluate("""() => {
            const panel = document.getElementById('inspector-panel');
            if (panel) panel.classList.remove('open');

            const slack = nodes.find(n =>
                n.properties && n.properties.bundle_id === 'com.tinyspeck.slackmacgap');
            if (slack) {
                enterFocusMode(slack.id);
                resetZoom();
            }
        }""")
        page.wait_for_timeout(500)
        out4 = output_dir / "04-electron-inheritance.png"
        page.screenshot(path=str(out4))
        screenshots.append(out4)
        print(f"  [4/9] {out4.name}")

        page.close()

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
            f.write(report_html)
            report_path = f.name

        page = browser.new_page(viewport={"width": 1200, "height": 900})
        page.goto(f"file://{report_path}")
        # Wait for Mermaid to render
        page.wait_for_timeout(3000)

        # Screenshot 5: Report summary (top section — already at top)
        out5 = output_dir / "05-report-summary.png"
        page.screenshot(path=str(out5))
        screenshots.append(out5)
        print(f"  [5/9] {out5.name}")

        # Screenshot 6: Attack path diagrams
        page.evaluate("""() => {
            const els = document.querySelectorAll('.mermaid svg, pre.mermaid svg');
            if (els.length > 0) {
                els[0].scrollIntoView({block: 'start'});
                return;
            }
            const headings = Array.from(document.querySelectorAll('h2, h3'));
            const pathH = headings.find(h => h.textContent.includes('Attack Path'));
            if (pathH) pathH.scrollIntoView({block: 'start'});
        }""")
        page.wait_for_timeout(500)
        page.set_viewport_size({"width": 1200, "height": 600})
        page.wait_for_timeout(200)
        out6 = output_dir / "06-attack-path-diagram.png"
        page.screenshot(path=str(out6))
        screenshots.append(out6)
        print(f"  [6/9] {out6.name}")

        # Screenshot 7: CVE / vulnerability table
        page.set_viewport_size({"width": 1200, "height": 500})
        page.evaluate("""() => {
            const headings = Array.from(document.querySelectorAll('h2, h3'));
            const vulnH = headings.find(h =>
                h.textContent.includes('Vulnerabilit') || h.textContent.includes('CVE'));
            if (vulnH) vulnH.scrollIntoView({block: 'start'});
        }""")
        page.wait_for_timeout(300)
        out7 = output_dir / "07-cve-table.png"
        page.screenshot(path=str(out7))
        screenshots.append(out7)
        print(f"  [7/9] {out7.name}")

        # Screenshot 8: Tier classification
        page.set_viewport_size({"width": 800, "height": 600})
        page.evaluate("""() => {
            const headings = Array.from(document.querySelectorAll('h2, h3'));
            const tierH = headings.find(h => h.textContent.includes('Tier'));
            if (tierH) tierH.scrollIntoView({block: 'start'});
        }""")
        page.wait_for_timeout(500)
        out8 = output_dir / "08-tier-pie.png"
        page.screenshot(path=str(out8))
        screenshots.append(out8)
        print(f"  [8/9] {out8.name}")

        page.close()

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
            f.write(cli_html)
            cli_path = f.name

        page = browser.new_page(viewport={"width": 900, "height": 600})
        page.goto(f"file://{cli_path}")
        page.wait_for_timeout(500)
        out9 = output_dir / "09-cli-output.png"
        page.screenshot(path=str(out9))
        screenshots.append(out9)
        print(f"  [9/9] {out9.name}")

        page.close()
        browser.close()

    return screenshots


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate screenshots for the Rootstock README"
    )
    parser.add_argument("--output-dir", "-o", default=str(ROOT / "docs" / "screenshots"),
                        help="Output directory for screenshots")
    parser.add_argument("--scan", default=None,
                        help="Scan JSON file (default: examples/demo-scan.json)")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Building mock graph from demo scan data...")
    scan_path = Path(args.scan) if args.scan else ROOT / "examples" / "demo-scan.json"
    scan = json.loads(scan_path.read_text())
    graph_data = build_mock_graph(scan)

    print("Generating viewer HTML...")
    viewer_html = generate_viewer_html(graph_data)

    print("Generating report HTML...")
    report_html = generate_report_html()

    print("Generating CLI terminal mockup...")
    cli_html = generate_cli_html()

    print("Taking screenshots with Playwright...")
    screenshots = take_screenshots(viewer_html, report_html, cli_html, output_dir)

    print(f"\nDone! {len(screenshots)} screenshots saved to {output_dir}/")
    for s in screenshots:
        size_kb = s.stat().st_size / 1024
        print(f"  {s.name} ({size_kb:.0f} KB)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
