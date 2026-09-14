# Frontend and report interface

Use the viewer to inspect a local graph or an exported snapshot. The
live viewer at `/` and rendered `*-viewer.html` files use the same HTML, CSS,
and JavaScript interaction model. Offline viewers are single files with no
external asset downloads.

The packaged template and generated browser assets live in
`graph/src/rootstock_graph/resources/viewer/`. Author modular styles in
`graph/viewer-css/` and typed code in `graph/viewer-src/`; `npm run bundle`
assembles them into the packaged assets. The renderer and API live under
`graph/src/rootstock_graph/reporting/viewer.py` and
`graph/src/rootstock_graph/api.py` and are exposed by `rootstock-graph-viewer`
and `rootstock-graph-api`.

The primary interface guides the reader through Scope, Evidence, Report, and
download. Graph tools opens the full triage, graph,
path, and query workspace.

## Investigate and export

- Connect to the local API with its bearer token. The viewer keeps the token
  in `sessionStorage` for the current tab.
- Review available scan metadata and collection gaps, then select an FDA,
  modeled-path, or recommendation question. Live mode executes the corresponding
  packaged query; offline mode inspects only relationships in the loaded snapshot.
- Inspect application evidence, distinguish observed grants from inferred paths,
  and review recommendations before preparing a Markdown or HTML download.
- Download a full assessment in live mode or a clearly labelled snapshot summary
  offline. The browser controls the destination; completion confirms that the
  download started, not that a file was saved to a particular directory.
- Triage a deterministic risk queue, open a finding dossier in place, and move
  selected evidence into graph inspection without losing context.
- Search and filter the Graph workspace, select nodes from the canvas or
  semantic list, inspect relationships, and control the viewport.
- Select endpoints, compute or reset an ordered route, and preserve a completed
  result when moving away from the Paths workspace.
- Run saved queries or read-only custom Cypher in live mode. Static viewers
  explain that queries need a live connection.
- In live mode, mark owned nodes, classify tiers, or refresh the graph. Both
  modes can export the current graph viewport as a PNG.
- Read and print graph and CVE reports at desktop and narrow widths.

## Graph navigation and layout

The node list shows 200 rows per page with Previous/Next controls and an
announced range. Filtering or refreshing starts at the first page; selecting
a visible node opens its page. Selection updates preserve unchanged rows.
Dragging updates only the moved node in the hit-test index. Canvas drawing
skips primitives outside the viewport while retaining intersecting labels and
edges. PNG export captures the current viewport.

Static layout uses exact repulsion through 256 nodes and deterministic
Barnes-Hut repulsion above that threshold (opening ratio 0.7, seed 42).
Interactions remain bounded to 500 world units. Layout retains the requested
iteration budget and may settle early after at least 20 iterations and ten
consecutive displacements below 0.1 world units. Layout coordinates affect the drawing, not the evidence or modeled paths.

## Try the synthetic demo

The GitHub Pages artifact is the real viewer running in static mode with a
deterministic synthetic graph. It supports canvas and list selection, search,
filters, the Triage, Graph, Paths, and Queries workspaces, dossier tabs, path
exploration, theme switching, zoom, and local PNG export. It does not connect
to Neo4j or the loopback API, run Cypher, store a bearer token, or mutate graph
state.

The demo opens at Scope and supports the complete offline evidence and summary
flow. Its deliberately partial scan keeps collection warnings visible. Graph
tools opens the existing workspaces without discarding the folio context.

Build and validate the self-contained page locally:

```bash
npm run demo:build
npm run demo:verify
```

The generated page is `graph/generated/pages-demo/index.html`. It is ignored
build output; the Pages workflow recreates it from the packaged production
template, styles, bundle, and `scripts/viewer-demo-data.mjs`.

The public screenshots use the same synthetic data and production viewer. See
[Screenshot capture](screenshots.md) for the browser setup, capture command,
privacy checks, and local preview.

## Storage and privacy

The API token is session-only. Theme preference and custom query history are
browser-local. Query history can be cleared from the interface. The frontend
contains no telemetry.

Reports, viewers, real scan data, tokens, query history, and images
containing real evidence are confidential artifacts. They must not be
committed.

## Accessibility and responsive behavior

The design target is WCAG 2.2 AA. Node selection, inspection, and path operations have
semantic DOM controls as alternatives to the graph canvas. At widths below 768 pixels and at high zoom, the list
and details become the primary interface. Reports reflow to 320 CSS
pixels, while wide tables retain semantic headers and labelled scrolling.

Keyboard behavior includes Tab and Shift+Tab navigation, Enter and Space on
controls, Escape for open menus and path mode, and Cmd+Enter or
Ctrl+Enter to run Cypher. Reduced-motion preference disables nonessential
transitions.

The folio stacks its context panel below the main task on narrow screens. Step
changes reset scroll and focus the task heading. Authentication makes the
background inert and focuses the token field; validation and request failures
use announced feedback. Empty results and unavailable evidence are explicit.

## Edit and check the viewer

Build and verify the frontend through the shared lane:

```bash
sh scripts/verify web
```

The lane typechecks and lints the viewer, runs Node logic tests, and compares a
temporary asset rebuild with the working-tree packaged assets. Run `npm run
bundle` after changing viewer source. Browser interaction and visual checks
are separate from this lane.

`node_modules/` and `graph/generated/` are local artifacts ignored by Git.
