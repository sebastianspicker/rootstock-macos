# Interface design

Rootstock is a security assessment instrument. Its interfaces follow the
conventions analysts already know from vulnerability scanners and graph-based
attack-path tools. They use dense, scannable layouts, standard severity
colours, monospace identifiers and tables. Decoration does not compete with
evidence.

This document applies to every rendered surface: the viewer and its Graph
tools workspace, the snapshot summary export, the PNG export, the graph and
CVE HTML reports, and the Pages demo and screenshot tour. See
[Frontend and report interface](docs/frontend.md) for behaviour and
[Screenshot capture](docs/screenshots.md) for reproducible examples.

## Principles

- **Evidence first.** Every screen shows the source, collection time and any
  collection gaps. Recorded facts, inferred relationships and missing
  evidence stay visually distinct. A modeled path shows preconditions. It
  does not establish compromise.
- **Density over ceremony.** Use compact rows, small labels and full-width
  tables. Do not add hero headings, slogans, oversized type, or decorative
  cards.
- **One meaning per colour.** Blue is for actions and focus. Violet is for
  inferred or modeled material. The severity scale is for severity. Amber is
  for collection gaps. Nothing borrows another role's colour.
- **Plain technical language.** Name things the way a scanner does: scan,
  snapshot, finding, evidence, path, report. Avoid metaphors. The viewer is
  not a folio, sheet, specimen, or lightbox.

## Tokens

All values are CSS custom properties in `graph/viewer/css/tokens.css`. The HTML
reports repeat the same values in their inline style blocks. Canvas code reads
`--ink`, `--ink-deep`, `--pane`, `--text`, `--muted`, `--subtle`, `--path`,
`--annotation`, `--edge`, `--edge-faint` and the four severity tokens by name,
so keep those names.

| Role | Token | Light | Dark |
| --- | --- | --- | --- |
| App ground | `--ink` | `#f4f6f9` | `#0d1117` |
| Inset / canvas / table body | `--ink-deep` | `#ffffff` | `#090c10` |
| Panel | `--pane` | `#ffffff` | `#131820` |
| Panel header, toolbar | `--pane-raised` | `#eef1f5` | `#1a212b` |
| Selected row | `--pane-selected` | `#e1ebfb` | `#1c2b45` |
| Hover wash | `--hover` | `rgba(15, 23, 42, 0.05)` | `rgba(148, 163, 184, 0.08)` |
| Selection wash | `--signal-dim` | `rgba(11, 92, 213, 0.10)` | `rgba(77, 148, 255, 0.14)` |
| Overlay | `--overlay` | `rgba(244, 246, 249, 0.96)` | `rgba(13, 17, 23, 0.96)` |
| Text | `--text` | `#0f172a` | `#e6edf3` |
| Secondary text | `--muted` | `#475569` | `#a6b1bd` |
| Tertiary text, labels | `--subtle` | `#5b6678` | `#8a96a3` |
| Hairline | `--rule` | `#dde3ea` | `#262e39` |
| Control border (≥ 3:1) | `--rule-strong` | `#768396` | `#6a7686` |
| Action | `--action` | `#0b5cd5` | `#1d6ae5` |
| Action hover | `--action-strong` | `#0948a8` | `#1558c7` |
| Text on action | `--on-action` | `#ffffff` | `#ffffff` |
| Link text | `--link` | `#0b5cd5` | `#4d94ff` |
| Focus ring | `--focus-ring` | `#0b5cd5` | `#4d94ff` |
| Inferred / modeled | `--annotation`, `--path` | `#6d28d9` | `#b392f0` |
| Inferred wash | `--annotation-dim`, `--path-dim` | `rgba(109, 40, 217, 0.08)` | `rgba(179, 146, 240, 0.12)` |
| Collection gap text | `--gap` | `#8a5a00` | `#e3b341` |
| Collection gap rule | `--gap-rule` | `#b07d00` | `#9e7a1e` |
| Collection gap wash | `--gap-dim` | `rgba(217, 154, 0, 0.12)` | `rgba(227, 179, 65, 0.10)` |
| Critical | `--critical` | `#b4123a` | `#ff5c7c` |
| High | `--high` | `#c2410c` | `#ff8f4d` |
| Medium | `--medium` | `#8f6a00` | `#e8c547` |
| Low | `--low` | `#0e7490` | `#4fc3d9` |
| Info / unscored | `--info` | `#5b6678` | `#8a96a3` |
| Verified / passing | `--verified` | `#15803d` | `#56d364` |
| Text on severity fill | `--on-severity` | `#ffffff` | `#0d1117` |
| Graph edge | `--edge` | `#475569` | `#8b96a5` |
| Faint graph edge | `--edge-faint` | `#334155` | `#6b7686` |

Theme follows the system by default. The viewer's theme control sets
`data-theme="light"` or `data-theme="dark"` on the root element.

### Type

- `--font-ui`: `-apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto,
  "Helvetica Neue", Arial, sans-serif`. Use it for all headings, text and
  controls.
- `--font-mono`: `"SF Mono", "JetBrains Mono", ui-monospace, Menlo, Consolas,
  "Liberation Mono", monospace`. Use it for identifiers, bundle IDs, paths,
  timestamps, hashes, CVE IDs, relationship kinds, counts in tables and query
  text.
- No serif faces, small caps, old-style numerals or decorative italics.
- Scale: `--size-1` 11px, `--size-2` 12px, `--size-3` 13px, `--size-4` 14px,
  `--size-5` 16px, `--size-6` 20px, `--size-7` 24px, `--size-8` 28px.
- Body text is 13px in Graph tools and 14px in the assessment flow. Page
  titles are 20–24px at weight 600. Nothing on screen exceeds 28px.
- Field and column labels are 11px, weight 600, uppercase, letter-spacing
  0.06em, in `--subtle`.
- Use tabular numerals (`font-variant-numeric: tabular-nums`) for counts and
  scores.

### Space, shape, elevation

- 4px spacing base (`--space-1` 4px through `--space-9` 96px, unchanged).
- `--radius` is 4px. Badges use 3px.
- Panels are flat: `--pane` background, 1px `--rule` border, no shadow.
- Only floating layers (menus, tooltips, popovers, the graph Key) use
  `--shadow-float`: `0 8px 24px rgba(15, 23, 42, 0.16)` in light and
  `0 8px 24px rgba(0, 0, 0, 0.5)` in dark.
- No gradients, glows, blurs, glassmorphism, or offset "paper" shadows.

## Components

- **App bar.** 48px tall, `--pane` background and bottom hairline. It holds
  the brand mark, the product name, a vertical divider, and the snapshot
  identity (host and collection time) in monospace. Status chips follow, such
  as SYNTHETIC, LIVE and PARTIAL COLLECTION. Actions sit on the right.
- **Brand mark.** A 22px square with radius 4px, `--text` background and
  `--ink` foreground, holding a monospace bold "R". The product name is 14px
  at weight 600.
- **Status chip.** 20px tall, 1px `--rule-strong` border, 11px uppercase
  text at weight 600. A gap chip uses `--gap` text and a `--gap-rule`
  border.
- **Severity badge.** A solid fill in the severity colour with
  `--on-severity` text, 11px uppercase at weight 700. The badge always
  includes the word (CRITICAL, HIGH, MEDIUM, LOW, INFO), and never colour
  alone.
- **Severity summary.** A row of count tiles. Each tile has a 3px left border
  in its severity colour, a 20px tabular count and an 11px uppercase label.
- **Step bar.** The assessment flow is Scope, Evidence, Report. Each step is
  a tab with a 18px numbered circle. The current step has a 2px `--action`
  underline and `--text` label. Unavailable steps use `--subtle`.
- **Panel.** Optional 36px header row with `--pane-raised` background and an
  uppercase label, then content with 16px padding.
- **Key–value table.** Used for scan metadata and node properties. Labels
  in the left column use the label style. Values are monospace when they are
  identifiers. Rows are separated by 1px `--rule`.
- **Data table.** Header row on `--pane-raised` with label-style headers.
  Rows are 32–36px with a 1px `--rule` separator, `--hover` on hover and
  `--pane-selected` with a 2px `--action` left edge when selected.
- **Links and text buttons.** Use `--link`, which meets 4.5:1 on every
  surface. `--action` is a fill colour and is not used for text.
- **Buttons.** Primary buttons use `--action` fill and `--on-action` text at
  weight 600. Secondary buttons use `--pane` fill and a `--rule-strong`
  border. Text buttons have no border. Height is 32px, or 36px for the main
  action of a step. Never use a severity colour on a button.
- **Inputs and selects.** 32px tall, `--ink-deep` fill, `--rule-strong`
  border. Focus shows a 2px `--focus-ring` outline with a 1px offset.
- **Gap alert.** `--gap-dim` background, 3px `--gap-rule` left border, a
  PARTIAL COLLECTION label in `--gap`, then the message in `--text`.
- **Evidence basis marks.** Observed is a solid 2px line in `--text`.
  Inferred is a dashed 2px line in `--annotation`. Not collected is a dotted
  line in `--subtle`. Each mark always appears with its word.
- **Modeled path.** Nodes are bordered boxes with a monospace detail line.
  Each joining relationship names its kind in monospace with its basis mark.
  The modeled starting point uses `--annotation`.

## Graph tools

Graph tools is a three-pane workbench. On the left is a 280px node index with
search, filters and the paged node list. The center holds Triage, Graph,
Paths and Queries. On the right is a 360px evidence inspector. The canvas
sits on `--ink-deep`. Observed relationships are solid `--edge` lines.
Inferred relationships are dashed `--annotation` lines. A modeled path is
drawn thicker in `--path` with numbered steps. Node kind colours come from
graph data and are not themed. The Key floats at the top left of the canvas
with `--shadow-float`.

## Controls and copy

Name actions by their result, such as Inspect snapshot, Prepare report and
Find modeled path. Distinguish loading, empty results, filtered results,
failed requests and partial collection. State which operations need a live
connection. Keep technical details beside the evidence they explain. Never
suggest that a finding is a confirmed exploit or that a recommendation has
been applied.

## Accessibility

WCAG 2.2 AA is the design target. Text meets 4.5:1 and control borders meet
3:1 against their backgrounds in both themes. Use semantic headings, labels,
buttons and tables. Graph selection and path construction are available
through DOM controls. Preserve keyboard focus after updates and respect
reduced-motion preferences. Automated checks are not proof of conformance.

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
JavaScript directly. After a visible change, inspect the rendered flow at
desktop and 390px widths and refresh the synthetic screenshots.
