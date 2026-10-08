# Frontend and report interface

Use the viewer to inspect a local graph or an exported snapshot. The
live viewer at `/` and rendered `*-viewer.html` files use the same HTML, CSS,
and JavaScript interaction model. Offline viewers are single files with no
external asset downloads.

The packaged template and generated browser assets live in
`graph/src/rootstock_graph/resources/viewer/`. Author modular styles in
`graph/viewer/css/` and typed code in `graph/viewer/src/`; `npm run bundle`
(run from `graph/viewer`) assembles them into the packaged assets. The renderer and API live under
`graph/src/rootstock_graph/reporting/viewer.py` and
`graph/src/rootstock_graph/api.py` and are exposed by `rootstock-graph-viewer`
and `rootstock-graph-api`.

The primary interface guides the reader through Scope, Evidence, Report, and
download. Graph tools opens the full triage, graph,
path, and query workspace.

## Investigate and export

- Connect to the local API with its bearer token. The viewer keeps the token
  in memory for the current page only; a reload asks for it again.
- Review available scan metadata and collection gaps, then select a question:
  apps with Full Disk Access and modeled injection (01), the shortest modeled
  path to Full Disk Access (02), recommendations (100), installed apps with
  NVD-matched CVEs (104), network listeners by exposure (106), custom trusted
  root certificates (107), browser extensions with access to every site or
  installed outside the store (108), launch items with `DYLD_*` injection (109),
  launch items whose program is missing (110) or user-writable (111), and host
  security settings (117). Each question names what it answers. Live mode
  executes the packaged query with the same id; offline mode answers from the
  nodes, relationships and properties in the loaded snapshot and returns the
  same columns. Rows that describe a listener, certificate, extension, launch
  item or host open that node in Graph tools.
- Inspect application evidence, distinguish observed grants from inferred paths,
  and review recommendations before preparing a Markdown or HTML download.
  The Evidence basis key labels each fact Observed, Inferred (violet) or Not
  collected; actions are blue and collection gaps are amber.
- Download a full assessment in live mode or a clearly labelled snapshot summary
  offline. The snapshot summary adds host settings, network listeners, the trust
  store, browser extensions, non-Apple installer receipts and NVD CVE counts
  when the snapshot contains them. The browser controls the destination; completion confirms that the
  download started, not that a file was saved to a particular directory.
- Read the host posture on the Scope page: the host's risk level, the settings
  that weaken it, and the settings the scan could not read.
- Triage a deterministic risk queue, open a finding dossier in place, and move
  selected evidence into graph inspection without losing context. Each dossier
  opens with a one-line explanation of the node kind, lists the reasons behind
  the risk score, and explains what every relationship asserts. Dossiers group
  the key facts of each kind before the remaining recorded fields: Host
  settings on the Computer (accounts, remote control, Software Update,
  XProtect, DNS, proxies, hosts entries, macOS CVE counts; an unread setting
  shows "Not collected"), arguments, `DYLD_*` environment (highlighted),
  triggers, load state, hash and containing bundle on launch items, the
  executable hash and download host on applications, and the endpoint,
  certificate, extension, receipt or process facts on those kinds.
  `AFFECTED_BY` rows say whether the version matched Rootstock's curated
  registry or an NVD CPE.
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
edges. PNG export captures the current viewport on the canvas ground color
and adds a footer with the host, snapshot time, the modeled-exposure caveat, and
the observed and inferred line samples.

Observed relationships are drawn as solid lines and inferred ones as
dashed violet lines; a modeled path is drawn thicker in violet with
numbered steps on its nodes. Traversable relationships end in an arrowhead and
non-traversable ones in a small open circle. The Key at the top left of the
Graph workspace explains these marks, the node shapes and severity marks, and
lists node kinds as buttons that hide or show each kind. A kind whose nodes carry
different colors shows a segmented swatch (up to four colors) in the Key and in
the node-kind filters, with a "n colours in this kind" note.
The header's provenance chip appears only when the status is Partial or
Unavailable, in the amber gap color, because collection gaps are evidence. Relationship labels
appear from 75% zoom when there are at most 150 visible relationships; from
that zoom they also appear for the modeled path and for the selected or hovered
node when the graph is denser. Below 45% zoom
only selected, hovered, and on-path nodes keep their labels. After a path is
found, Paths lists its steps in order, with each relationship's kind, whether
it is observed or inferred, and whether it is traversable.

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
tools opens the existing workspaces without discarding the assessment context. Its Back to assessment button returns to the flow.

Build and validate the self-contained page locally:

```bash
cd graph/viewer
npm ci --ignore-scripts
npm run demo:build
npm run demo:verify
```

The generated page is `graph/generated/pages-demo/index.html`. It is ignored
build output; the Pages workflow recreates it from the packaged production
template, styles, bundle, and `graph/viewer/scripts/viewer-demo-data.mjs`.

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

The assessment flow stacks its context panel below the main task on narrow screens. Step
changes reset scroll and focus the task heading. Authentication makes the
background inert and focuses the token field; validation and request failures
use announced feedback. Empty results and unavailable evidence are explicit.

## Edit and check the viewer

Build and verify the frontend through the shared lane:

```bash
sh scripts/verify web
```

The lane typechecks and lints the viewer, runs private Node logic tests only when
installed locally, and compares a
temporary asset rebuild with the working-tree packaged assets. Run `npm run
bundle` in `graph/viewer` after changing viewer source. Browser interaction and visual checks
are separate from this lane.

`graph/viewer/node_modules/` and `graph/generated/` are local artifacts ignored by Git.
