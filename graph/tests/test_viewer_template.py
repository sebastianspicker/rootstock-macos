from pathlib import Path
import sys
from unittest import TestCase


ASSET_DIR = Path(__file__).resolve().parents[1]
TEMPLATE = ASSET_DIR / "viewer_template.html"
STYLES = ASSET_DIR / "viewer.css"
SOURCE_DIR = ASSET_DIR / "viewer-src"
BUNDLE = ASSET_DIR / "viewer.bundle.js"
checks = TestCase()


def test_viewer_uses_one_generated_javascript_asset():
    authored_javascript = sorted(path.name for path in ASSET_DIR.glob("viewer*.js"))

    checks.assertEqual(authored_javascript, ["viewer.bundle.js"])
    checks.assertTrue(BUNDLE.is_file())
    checks.assertGreater(BUNDLE.stat().st_size, 1_000)


def test_typescript_source_is_modular_and_strict_checkable():
    expected = {
        "canvas.ts",
        "app.ts",
        "controls.ts",
        "dom.ts",
        "inspector.ts",
        "live.ts",
        "main.ts",
        "model.ts",
        "protocol.ts",
        "runtime.ts",
        "spatial.ts",
        "storage.ts",
        "types.ts",
        "view.ts",
    }
    checks.assertEqual({path.name for path in SOURCE_DIR.glob("*.ts")}, expected)
    source = "\n".join((SOURCE_DIR / name).read_text() for name in sorted(expected))

    checks.assertNotIn("@ts-nocheck", source)
    checks.assertNotIn("module.exports", source)
    checks.assertNotIn(".innerHTML", source)
    checks.assertIn('from "./app"', (SOURCE_DIR / "main.ts").read_text())
    checks.assertIn('from "./model"', (SOURCE_DIR / "app.ts").read_text())
    checks.assertIn('from "./inspector"', (SOURCE_DIR / "app.ts").read_text())
    checks.assertIn('from "./protocol"', (SOURCE_DIR / "app.ts").read_text())
    checks.assertIn('from "./spatial"', (SOURCE_DIR / "app.ts").read_text())
    checks.assertIn("window.RootstockViewer = Object.freeze({mount})", source)


def test_bundle_defers_dom_lookup_until_mount_and_exposes_one_api():
    source = (SOURCE_DIR / "app.ts").read_text()
    entrypoint = (SOURCE_DIR / "main.ts").read_text()
    mount_index = source.index("function mount(")
    collect_index = source.index("const dom = collectDom()", mount_index)

    checks.assertLess(mount_index, collect_index)
    checks.assertEqual(entrypoint.count("window.RootstockViewer ="), 1)
    checks.assertNotIn("window.liveRefresh", entrypoint)
    checks.assertNotIn("window.enterFocusMode", entrypoint)


def test_renderer_produces_self_contained_static_html():
    sys.path.insert(0, str(ASSET_DIR))
    from viewer import render_viewer_html

    payload = {
        "metadata": {"hostname": "</script><script>alert(1)</script>"},
        "graph": {"nodes": [], "edges": []},
    }
    rendered = render_viewer_html(
        payload,
        title='Host <script>alert("x")</script>',
        mode="static",
        api_base_url="</script>/api",
    )

    checks.assertNotIn("{{VIEWER_", rendered)
    checks.assertIn("&lt;script&gt;", rendered)
    checks.assertIn("<\\/script>", rendered)
    checks.assertIn('"mode": "static"', rendered)
    checks.assertIn("RootstockViewer.mount(", rendered)
    checks.assertNotIn("src=", rendered)


def test_renderer_replaces_only_original_template_placeholders():
    sys.path.insert(0, str(ASSET_DIR))
    from viewer import render_viewer_html

    rendered = render_viewer_html(
        {"graph": {"nodes": [], "edges": []}, "note": "{{VIEWER_CSS}} {{VIEWER_BOOTSTRAP}}"},
        title="{{VIEWER_JS}} {{VIEWER_TITLE}}",
        mode="static",
    )

    checks.assertIn("{{VIEWER_JS}} {{VIEWER_TITLE}}", rendered)
    checks.assertIn("{{VIEWER_CSS}} {{VIEWER_BOOTSTRAP}}", rendered)


def test_viewer_shell_has_valid_landmarks_and_no_inline_handlers():
    source = TEMPLATE.read_text()

    checks.assertEqual(source.count('<div id="app">'), 1)
    checks.assertIn('<header id="status-bar">', source)
    checks.assertIn('<nav id="global-nav"', source)
    checks.assertIn('<aside id="sidebar"', source)
    checks.assertIn('<section id="risk-posture"', source)
    checks.assertIn('<main id="graph-container"', source)
    checks.assertIn('<aside id="detail-dock"', source)
    checks.assertIn('<footer id="provenance-timeline"', source)
    checks.assertNotIn(" onclick=", source)
    checks.assertNotIn(" onchange=", source)
    checks.assertIn('type="password"', source)
    checks.assertIn('aria-describedby="graph-description"', source)
    checks.assertIn('aria-label="Rootstock attack graph visualization"', source)
    checks.assertIn('<div id="tooltip" role="tooltip" hidden>', source)


def test_viewer_controls_are_labelled_and_stateful():
    source = TEMPLATE.read_text()

    checks.assertIn('for="search">Search nodes</label>', source)
    checks.assertIn('role="tablist"', source)
    checks.assertIn('aria-selected="true"', source)
    checks.assertIn('aria-pressed="true"', source)
    checks.assertIn('aria-label="Close query results"', source)
    checks.assertIn('aria-label="Close details"', source)
    checks.assertIn('aria-label="Graph zoom controls"', source)
    checks.assertIn('id="evidence-coverage"', source)


def test_viewer_assets_define_theme_reflow_and_event_driven_rendering():
    script = (SOURCE_DIR / "app.ts").read_text()
    styles = STYLES.read_text()

    checks.assertIn("rootstock.theme", script)
    checks.assertIn("ResizeObserver", script)
    checks.assertIn("markDirty", script)
    checks.assertIn("@media (max-width: 767px)", styles)
    checks.assertIn("prefers-reduced-motion", styles)
    checks.assertIn(':root[data-theme="light"]', styles)
    checks.assertIn("grid-template-columns: 248px minmax(0, 1fr) 320px", styles)
    checks.assertIn("#provenance-timeline", styles)
