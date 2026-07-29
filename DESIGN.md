# Rootstock Design System

## Overview

Rootstock uses the Graphite Laboratory visual language: a forensic
instrument for authorized analysts on a 13–16-inch MacBook. Design serves the
investigation task: modeled attack paths, evidence, and provenance. The system
follows the OS theme by default and allows a persistent
light or dark override.

## Theme

- Color strategy: restrained mineral neutrals; semantic color only for action,
  selection, path focus, severity, and success.
- Modes: system, light, and dark. Persist only `rootstock.theme`.
- Motion: 120–180ms state changes; instant under `prefers-reduced-motion`.
- Elevation: tonal layers and hairline rules; avoid large soft shadows.

## Color Tokens (Graphite Lab)

| Role | Dark | Light | CSS variable |
|---|---|---|---|
| Void / canvas | `#090b0f` / `#0c0e13` | cool off-white | `--ink` / `--ink-deep` |
| Surface | `#10131a` | `#ffffff` | `--pane` |
| Raised | `#151922` | raised cool gray | `--pane-raised` |
| Border | `rgba(255,255,255,0.06)` | cool rule | `--rule` |
| Text | `#eceef2` | near-ink | `--text` |
| Muted / faint | `#8b93a7` / `#5c6478` | muted cool | `--muted` / `--subtle` |
| Signal (action) | `#6aafff` | deep blue | `--action` |
| Path | `#6ecfbc` | teal | `--path` |
| Brand / critical | rootstock red / `#f07178` | deep red | brand / `--critical` |
| High / success | `#d9a04a` / `#5cbc80` | amber / green | `--high` / `--verified` |

Severity never relies on color alone. Path focus uses mint edges and dimmed
non-path nodes.

## Typography

- UI: `"IBM Plex Sans"`, system UI stack.
- Mono: `"IBM Plex Mono"`, SF Mono, Menlo, Consolas.
- Body ~13px; technical values in mono; display titles reserved for the dossier
  heading (~20–22px). Letter-spacing on the wordmark only.

## Spacing and Shape

- Spacing: 4, 8, 12, 16, 24, 32px.
- Radius: 8px panels/controls; pills for nav and tags.
- Quiet density: more space in chrome, denser only in data lists.

## Layout (viewer)

```
Header 52px: brand, host, navigation, session, export
Workspace: 248px index | fluid stage | 320px evidence
  Stage: risk and path metadata | canvas
Footer 40px: provenance line
```

- Secondary chrome uses `.chrome-secondary` (de-emphasized or hidden).
- Path investigation is the hero state; graph tools stay available but quiet.
- Narrow &lt;768px: list-first stack; canvas remains reachable.

## Components

Buttons, fields, tabs, filters, dossier rows, and path banners share default,
hover, focus, active, disabled, and error states. Focus rings use `--action`.
The dossier is title-first: kicker, title, short subtitle, severity, evidence
tabs, plain model note, single primary action.

## Content

Analyst language: “Run query,” “Modeled path,” “Modeled preconditions do not
prove exploitation.” Distinguish empty, filtered-empty, error, and partial
evidence. Do not claim confirmed exploit.

## Authoring CSS

Source modules live in `graph/viewer-css/`. Assemble with:

```bash
npm run bundle:css
# or
npm run bundle   # CSS + JS
```

Do not hand-edit assembled `graph/viewer.css` for feature work. Edit the source
modules.
