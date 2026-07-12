from pathlib import Path
from unittest import TestCase


TEMPLATE = Path(__file__).resolve().parents[1] / "viewer_template.html"
ASSET_DIR = Path(__file__).resolve().parents[1]
SCRIPT_FILES = (
    "viewer.js",
    "viewer_spatial.js",
    "viewer_render.js",
    "viewer_analysis.js",
    "viewer_controls.js",
    "viewer_live.js",
    "viewer_shell.js",
)
STYLES = Path(__file__).resolve().parents[1] / "viewer.css"


def _script_source() -> str:
    return "\n".join((ASSET_DIR / name).read_text() for name in SCRIPT_FILES)


def _between(source: str, start: str, end: str) -> str:
    start_index = source.index(start)
    end_index = source.index(end, start_index)
    return source[start_index:end_index]


checks = TestCase()


def test_viewer_renders_graph_values_through_text_sinks():
    source = _script_source()

    checks.assertNotIn(".innerHTML", source)
    checks.assertIn("textContent: node.label || '?'", source)
    checks.assertIn("title.textContent = d.label || d.id", source)
    checks.assertIn(
        "td.textContent = Array.isArray(val) ? val.join(', ') : String(val ?? '')",
        source,
    )
    checks.assertIn("tooltip.textContent = ''", source)


def test_live_query_failures_render_error_instead_of_positive_no_findings():
    source = _script_source()
    run_live_query = _between(
        source, "function runLiveQuery", "function highlightQueryResult"
    )

    checks.assertIn("throw new Error('Malformed query response')", run_live_query)
    checks.assertIn("meta.textContent = 'Error: ' + err.message", run_live_query)
    checks.assertIn("textContent: 'Query failed'", run_live_query)
    checks.assertIn("textContent: err.message", run_live_query)
    checks.assertIn("textContent: 'No results.'", run_live_query)
    checks.assertIn("No findings", run_live_query)
    checks.assertLess(
        run_live_query.index("throw new Error('Malformed query response')"),
        run_live_query.index(".catch(err =>"),
    )
    checks.assertLess(
        run_live_query.index("body.appendChild(el('div', {textContent: 'No results.'"),
        run_live_query.index("No findings"),
    )


def test_live_actions_fail_visibly_and_preserve_unsaved_owned_state():
    source = _script_source()
    live_refresh = _between(source, "function liveRefresh", "function liveTierClassify")
    live_tier = _between(source, "function liveTierClassify", "function liveShowOwned")
    live_show_owned = _between(
        source, "function liveShowOwned", "// \u2500\u2500 Custom Cypher"
    )
    toggle_override = _between(source, "// Override toggleOwned", "// Keyboard: Escape")

    checks.assertIn("throw new Error('Malformed graph response')", live_refresh)
    checks.assertIn(
        "setLiveStatus('Graph refresh failed: ' + err.message, 'error')",
        live_refresh,
    )
    checks.assertLess(
        live_refresh.index("throw new Error('Malformed graph response')"),
        live_refresh.index("replaceGraphData(data)"),
    )
    checks.assertIn("throw new Error('Malformed tier response')", live_tier)
    checks.assertIn(
        "setLiveStatus('Tier classification failed: ' + err.message, 'error')",
        live_tier,
    )
    checks.assertIn("throw new Error('Malformed owned response')", live_show_owned)
    checks.assertIn(
        "setLiveStatus('Show owned failed: ' + err.message, 'error')",
        live_show_owned,
    )
    checks.assertIn("const wasOwned = d.properties?.owned === true", toggle_override)
    checks.assertIn("d.properties.owned = !wasOwned", toggle_override)
    checks.assertIn("d.properties.owned = wasOwned", toggle_override)
    checks.assertIn(
        "setLiveStatus(action + ' failed: ' + err.message, 'error')",
        toggle_override,
    )


def test_viewer_shell_has_valid_landmarks_and_no_inline_handlers():
    source = TEMPLATE.read_text()

    checks.assertEqual(source.count('<div id="app">'), 1)
    checks.assertIn('<header id="status-bar">', source)
    checks.assertIn('<aside id="sidebar"', source)
    checks.assertIn('<main id="graph-container"', source)
    checks.assertIn('<aside id="detail-dock"', source)
    checks.assertNotIn(" onclick=", source)
    checks.assertNotIn(" onchange=", source)
    checks.assertIn('type="password"', source)
    checks.assertIn('aria-describedby="graph-description"', source)
    checks.assertIn('aria-label="Rootstock attack graph visualization"', source)
    checks.assertIn('<div id="tooltip" role="tooltip" hidden>', source)


def test_viewer_controls_are_labelled_and_stateful():
    source = TEMPLATE.read_text()

    checks.assertIn('<label for="search">Search nodes</label>', source)
    checks.assertIn('role="tablist"', source)
    checks.assertIn('aria-selected="true"', source)
    checks.assertIn('aria-pressed="true"', source)
    checks.assertIn('aria-label="Close query results"', source)
    checks.assertIn('aria-label="Close details"', source)


def test_viewer_assets_define_theme_reflow_and_event_driven_rendering():
    script = _script_source()
    styles = STYLES.read_text()

    checks.assertIn("rootstock.theme", script)
    checks.assertIn("ResizeObserver", script)
    checks.assertIn("class SpatialGrid", script)
    checks.assertNotIn("if (!dirty) { requestAnimationFrame(draw)", script)
    checks.assertIn("@media (max-width: 767px)", styles)
    checks.assertIn("prefers-reduced-motion", styles)
    checks.assertIn(":root[data-theme=\"light\"]", styles)
