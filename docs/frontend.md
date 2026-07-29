# Frontend and report interface

Rootstock's frontend is a local analysis interface, not a hosted dashboard. The
live viewer at `/` and rendered `*-viewer.html` files use the same HTML, CSS,
and JavaScript interaction model. Offline viewers are single files with no
runtime asset dependency.

The maintained source is `graph/viewer_template.html`, modular styles in
`graph/viewer-css/` (assembled to `graph/viewer.css`), and the typed files in
`graph/viewer-src/`. `npm run bundle` assembles CSS and writes
`graph/viewer.bundle.js`. Both `graph/viewer.py` and `graph/server.py` use the
same renderer.

The live visual system is Graphite Laboratory: quiet forensic chrome, path-first
stage, and a title-first evidence dossier. Author styles in `graph/viewer-css/`
and rebuild with `npm run bundle:css` rather than editing assembled
`graph/viewer.css` by hand.

## Implemented workflows

- Store the API token only in `sessionStorage` and connect to the local API.
- Search and filter the graph, select nodes from the canvas or semantic list,
  inspect relationships, and construct an ordered path.
- Run saved queries or read-only custom Cypher and inspect tabular results.
- Mark owned nodes, classify tiers, refresh data, and export a PNG.
- Read and print graph and CVE reports at desktop and narrow widths.

## Storage and privacy

The API token is session-only. Theme preference and custom query history are
browser-local. Query history can be cleared from the interface. The frontend
contains no telemetry.

Reports, viewers, real scan data, tokens, query history, and images
containing real evidence are confidential artifacts. They must not be
committed.

Public release images use the seven-node synthetic fixture in
`scripts/release-screenshot-fixture.mjs`. The script
`scripts/capture-release-screenshots.mjs` mounts the maintained viewer assets
with that fixture and captures four states directly in Playwright. These images
verify production rendering and local interactions with synthetic data; they
do not verify live Neo4j or authenticated API behavior.

## Accessibility and responsive behavior

The design target is WCAG 2.2 AA. The graph canvas is a two-dimensional
exception, but node selection, inspection, and path operations also have
semantic DOM controls. At widths below 768 pixels and at high zoom, the list
and details surface becomes the primary interface. Reports reflow to 320 CSS
pixels, while wide tables retain semantic headers and labelled scrolling.

Keyboard behavior includes Tab and Shift+Tab navigation, Enter and Space on
controls, Escape for transient surfaces and path mode, and Cmd+Enter or
Ctrl+Enter to run Cypher. Reduced-motion preference disables nonessential
transitions.

## Browser and release verification

The automated lane uses Playwright's revision-pinned Chromium at desktop,
compact, and 320-pixel widths. It includes axe checks for static and mocked-live
states. Safari, Firefox, mobile browsers, and VoiceOver are not part of the
automated matrix for this alpha and require separate manual checks.

A live authenticated Neo4j fixture is required before claiming end-to-end API
and graph runtime verification. Static and mocked browser tests do not provide
that evidence.

Install the locked development dependencies and run the frontend checks:

```bash
npm ci --no-audit --no-fund --ignore-scripts
npx --no-install playwright install chromium
npm run typecheck
npm run bundle
npm run test:viewer:unit
npm run test:viewer:bundle
npm run test:viewer:performance
npm run test:browser
npm run screenshots:release
```

If the pinned Playwright browser cannot be installed but a compatible local
Chromium executable is already present, set `ROOTSTOCK_BROWSER_PATH` to that
executable for `npm run test:browser` and `npm run screenshots:release`. Record
that substitution in validation results.

`node_modules/`, Playwright reports, traces, HAR files, and routine test images
are local artifacts ignored by Git.

The performance contract uses a synthetic graph with 10,000 nodes and 50,000
edges. It requires stopped idle rendering, hit-testing p95 below 16 ms, and
filter/search p95 below 100 ms on the recorded environment. Results from one
host are not a general browser performance claim.
