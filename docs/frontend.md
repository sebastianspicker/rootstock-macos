# Frontend and report interface

Rootstock's frontend is a local forensic workstation, not a hosted dashboard.
The live viewer at `/` and generated `*-viewer.html` files share the same vanilla
HTML, CSS, and JavaScript interaction model. Generated viewers remain single-file
and dependency-free at runtime.

The maintained source is split across `graph/viewer_template.html`,
`graph/viewer.css`, and `graph/viewer.js`. `graph/viewer.py` inlines those assets
for offline viewers, while `graph/server.py` assembles the same source for the
authenticated live route. There is no frontend runtime framework or external
asset request.

## Supported workflows

- Connect with the API token held only in `sessionStorage`.
- Search and filter the graph, select a node from Canvas or the synchronized list,
  inspect properties and relationships, and construct an ordered path.
- Run categorized saved queries or read-only custom Cypher, review ordered results,
  and highlight mapped nodes.
- Mark owned nodes, classify tiers, refresh data, and export a PNG.
- Read and print semantic graph and CVE reports on desktop or narrow screens.

## Storage and privacy

The API token is session-only. The theme preference is stored as
`rootstock.theme`. Custom Cypher history is local to the browser and can be
cleared from the Queries view. Rootstock has no frontend telemetry. Generated
reports, viewers, scan data, tokens, browser history, and screenshots containing
real evidence must not be committed.

Release screenshots are generated from the synthetic examples and reviewed for
hostnames, usernames, paths, and metadata before publication. Routine browser
captures remain ignored local test artifacts.

## Accessibility and responsive behavior

The target is WCAG 2.2 AA. Canvas is a two-dimensional exception, but equivalent
node selection, inspection, and path operations are available in semantic DOM.
At widths below 768px and at high zoom, the list and detail drawer become the
primary interface. Reports reflow to 320 CSS pixels; wide tables use labelled
horizontal wrappers and retain semantic headers.

Keyboard support includes Tab/Shift+Tab, Enter and Space on controls, Escape to
close transient surfaces or cancel path mode, and Cmd/Ctrl+Enter to run Cypher.
Reduced-motion preferences disable nonessential transitions.

## Browser and release verification

The release target covers current and previous Safari, Chrome, and Firefox on
supported macOS, plus current iOS Safari and Android Chrome for reports. The
checked-in Playwright lane currently exercises installed Google Chrome at desktop,
compact, and 320-pixel widths, with axe checks for static and mocked-live states.
The broader browser matrix and VoiceOver workflow remain manual release checks.
A live authenticated Neo4j fixture is required before claiming end-to-end graph
runtime completion; otherwise report the result as locally clean but partially
verified.

Install the approved dev-only browser dependencies with `npm install`, then run
the static and mocked-live browser lane with `npm run test:browser`. The default
configuration uses the installed Google Chrome channel and does not add a
frontend runtime dependency. `node_modules/`, Playwright reports, traces, HAR
files, and test screenshots are local artifacts ignored by git.

The interaction performance contract is 10,000 nodes and 50,000 edges, with idle
rendering stopped, hit-testing p95 below 16ms, and filter/search p95 below 100ms on
the recorded reference environment.
