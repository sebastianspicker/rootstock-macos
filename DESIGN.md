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

The folio uses a task column and a narrower context column. On small screens,
the context follows the task. Each step focuses its heading and returns to the
top of the document.

Graph tools uses a searchable node list, a central workspace, and an evidence
inspector. Triage, Graph, Paths, and Queries share the same selected data.
The node list provides an alternative to choosing nodes on the canvas.

## Color and typography

Dark surfaces, fine borders, and green action controls define the default
folio. The graph also offers system, light, and dark themes. Severity has a
text label as well as a color; inference uses labels and dashed relationships.

Use the existing CSS variables for text, surfaces, borders, actions, and
severity. The base palette lives in `graph/viewer-css/base.css`; folio styles
and dark-theme overrides live in `graph/viewer-css/folio.css`. Read those
files for the current values.

Use the UI font stack for prose and controls. Use the monospace stack for
identifiers, timestamps, paths, and query text. Fonts must remain usable without
an external font download.

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

Edit TypeScript in `graph/viewer-src/` and CSS in `graph/viewer-css/`, then run:

```sh
npm run bundle
sh scripts/verify web
```

The bundle command updates the packaged assets under
`graph/src/rootstock_graph/resources/viewer/`. Do not edit generated CSS or
JavaScript directly. After a visible change, inspect the rendered flow and
refresh the synthetic screenshots when needed.
