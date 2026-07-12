# Rootstock Design System

## Overview

Rootstock uses a restrained forensic-workstation language for an authorized
analyst working on a 13–16-inch MacBook in mixed office light. The system follows
the operating-system theme by default and permits a persistent light or dark
override. It favors compact, familiar controls and flat tonal hierarchy.

## Theme

- Color strategy: restrained neutral surfaces with semantic color reserved for
  action, selection, severity, success, and graph meaning.
- Modes: system, light, and dark. Store only the preference as
  `rootstock.theme`; tokens and scan evidence remain outside persistent storage.
- Motion: 120–180ms state transitions; instant under `prefers-reduced-motion`.
- Elevation: tonal layers by default and one restrained overlay shadow.

## Color Tokens

| Role | Dark | Light |
|---|---|---|
| Canvas | `#0b1016` | `#f4f7fa` |
| Surface | `#131a22` | `#ffffff` |
| Raised surface | `#1b2430` | `#eaf0f5` |
| Border | `#344253` | `#c4ced8` |
| Primary text | `#f3f6f9` | `#17212b` |
| Muted text | `#aeb8c4` | `#526273` |
| Subtle text | `#8c99a8` | `#66788a` |
| Action | `#6aafff` | `#0a61c9` |
| Brand | `#e05260` | `#b72f3f` |
| Critical | `#ff6b72` | `#bd2432` |
| Warning/high | `#f2b84b` | `#8a5a00` |
| Success/low | `#59c77a` | `#116b36` |

Use translucent semantic fills only with a text or icon label. Graph categories
may use six color/shape families, but exact type labels remain visible.

## Typography

- UI: `-apple-system`, `BlinkMacSystemFont`, `SF Pro Text`, `Helvetica Neue`, sans-serif.
- Technical values: `SF Mono`, Menlo, Consolas, monospace.
- Body and controls: 13–14px; metadata: 12px; headings: 16–20px.
- Do not use essential text below 12px or repeated uppercase tracked headings.
- Prose lines remain within 65–75 characters; tables and technical data may run wider.

## Spacing and Shape

- Spacing scale: 4, 8, 12, 16, 24, 32px.
- Radius: 4px controls and 8px panels/overlays; pills only for true tags.
- Controls: 32px compact desktop, 40px default, 44px narrow or touch mode.
- Breakpoints: 1024px compact desktop and 768px narrow mode.
- Z-index order: toolbar, sticky header, drawer backdrop, drawer, status, tooltip.

## Layout

- Top status bar: identity, provenance, connection, counts, and theme.
- Left rail: Explore and Queries tabs, filters/list or query tools.
- Main workspace: Canvas, grouped toolbar, path instruction, graph summary.
- Right dock: a single contextual surface for Node, Path, and Query results.
- Narrow mode: collapsible rail and full-width detail drawer; semantic list-first
  exploration is primary while Canvas remains available.
- Reports: responsive reading column, semantic sections, scroll-wrapped tables,
  captions, and a print theme.

## Components and States

Buttons, fields, tabs, filter rows, status chips, inline feedback, the detail
dock, and data tables share default, hover, focus, active/selected, disabled,
loading, success, warning, and error states. Use native elements and ARIA only
where native semantics do not express the state. Focus rings use the action color
with at least 2px visible separation.

Canvas exposes an accessible description and points to the synchronized node
list. Selection, path steps, results, and mutations announce through polite or
assertive live regions as appropriate. Low-risk owned/tier toggles remain
reversible and do not require confirmation.

## Content

Use direct analyst language: “Run query,” “No nodes match these filters,” and
“Session expired; enter the token again.” Distinguish empty data, filtered-empty,
malformed response, timeout, permission failure, and stale data. Preserve Cypher,
node types, relationship names, and provenance rather than translating them into
consumer terminology.
