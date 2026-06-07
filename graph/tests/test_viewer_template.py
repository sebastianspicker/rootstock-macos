from pathlib import Path
from unittest import TestCase


TEMPLATE = Path(__file__).resolve().parents[1] / "viewer_template.html"


def _between(source: str, start: str, end: str) -> str:
    start_index = source.index(start)
    end_index = source.index(end, start_index)
    return source[start_index:end_index]


checks = TestCase()


def test_viewer_renders_graph_values_through_text_sinks():
    source = TEMPLATE.read_text()

    checks.assertNotIn(".innerHTML", source)
    checks.assertIn("textContent: d.label || '?'", source)
    checks.assertIn("title.textContent = d.label || d.id", source)
    checks.assertIn(
        "td.textContent = Array.isArray(val) ? val.join(', ') : String(val ?? '')",
        source,
    )
    checks.assertIn("tooltip.textContent = ''", source)


def test_live_query_failures_render_error_instead_of_positive_no_findings():
    source = TEMPLATE.read_text()
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
    source = TEMPLATE.read_text()
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
