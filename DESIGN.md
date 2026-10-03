# Viewer design

The viewer helps analysts move from a security question to its supporting
facts, modeled relationships, and a report. The main flow is Scope →
Evidence → Report. Graph tools opens a second workspace for triage, node
inspection, paths, and queries.

This document describes the interface conventions. See
[Frontend and report interface](docs/frontend.md) for behavior and
[Screenshot capture](docs/screenshots.md) for reproducible examples.

## Evidence comes first

Start with the source, collection time, and any collection gaps. Keep recorded
facts, inferred relationships, and missing evidence distinct. A modeled path
shows preconditions; it does not establish compromise.

The evidence screen places the selected application's path and facts beside
recommendations and installation details. Report preparation names the output
and its scope before download. Static mode exports a snapshot summary; live
mode can generate the full graph assessment.

## Layout

The folio is a sheet with a margin: a task column for the question, path, and
facts, and a narrower margin column for the reading key, recommendations, and
identity. On screens below 860 pixels the margin follows the task. Collection
metadata is set as a ruled specimen label. Each step focuses its heading and
returns to the top of the document. The footer stays in reach and holds the
step's actions.

Graph tools uses a searchable node list, a central workspace, and an evidence
inspector. Triage, Graph, Paths, and Queries share the same selected data.
The node list provides an alternative to choosing nodes on the canvas. On
phones, the Triage, Paths, and Queries workspaces come before the node list.

## Color and typography

The interface is ink on paper. Dark mode shows the same sheet on a lightbox.
Theme follows the system by default; the folio and Graph tools both offer a
theme control. All values are tokens in `graph/viewer/css/tokens.css`.

- Actions are set in ink (solid ink buttons). They never borrow a severity hue.
- Pencil blue (`--annotation`, also `--path`) marks inferred and modeled
  material only: dashed relationships, the modeled starting point, analysis
  notes, and highlighted paths. Do not use it for anything else.
- Severity uses earth pigments (`--critical`, `--high`, `--medium`, `--low`)
  and always appears with its word.
- Collection gaps use the ochre `--gap` band. The oxide red `--oxide` is
  reserved for the brand mark.

Three type families, all installed locally or system-provided, so offline
viewers download nothing:

- `--font-serif` (Iowan Old Style, falling back to Charter and Georgia) for
  headings, lead text, and field names, set in small caps.
- `--font-ui` (the system sans) for controls, tables, and dense UI.
- `--font-mono` for identifiers, timestamps, paths, relationship names, and
  query text.

Use the `--size-*` and `--space-*` scales rather than ad-hoc values. Radius
is 2px. Floating panels use the offset `--slip-shadow`, not blurred shadows.
Node kind colors come from graph data and are not themed.

## Controls and copy

Name actions by their result: Inspect snapshot, Prepare report, Find modeled
path. Distinguish loading, empty results, filtered results, failed requests,
and partial collection. State which operations require a live connection.

Keep focus, selection, disabled, and error states visible. Technical details
belong beside the evidence they explain. Avoid language that suggests a
finding is a confirmed exploit or that a recommendation has been applied.

## Accessibility

WCAG 2.2 AA is the design target. Use semantic headings, labels, buttons, and
tables. Make graph selection and path construction available through DOM
controls. Preserve keyboard focus after updates and respect reduced-motion
preferences. Do not treat automated checks as proof of conformance.

Review changes at desktop and narrow widths, including long paths, missing
metadata, empty results, and errors. The screenshot workflow checks the main
folio at 390 pixels; it does not cover every graph interaction or assistive
technology.

## Editing the interface

Edit TypeScript in `graph/viewer/src/` and CSS in `graph/viewer/css/`, then run
from `graph/viewer`:

```sh
npm ci --ignore-scripts
npm run bundle
cd ../..
sh scripts/verify web
```

The bundle command updates the packaged assets under
`graph/src/rootstock_graph/resources/viewer/`. Do not edit generated CSS or
JavaScript directly. After a visible change, inspect the rendered flow and
refresh the synthetic screenshots when needed.
