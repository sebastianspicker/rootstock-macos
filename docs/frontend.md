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

## Build verification

Build the frontend directly:

```bash
npm run typecheck
npm run bundle
```

`node_modules/` and generated build output are local artifacts ignored by Git.
