# Screenshot capture

The [README tour](../README.md#screenshot-tour) and the Pages screenshot tour
use the same four PNGs in `docs/assets/screenshots/`. They show the viewer running with `scripts/viewer-demo-data.mjs`, a fictional dataset.
Never substitute captures from a real scan or case.

## Reproduce the tour

From the repository root, use Node from `.node-version` and the npm version
in `package.json`:

```sh
npm ci --ignore-scripts
npm run bundle
npm run demo:build
npm run demo:screenshots
npm run demo:build
npm run demo:verify
```

Screenshot capture needs an existing Playwright installation and a compatible
Chromium browser. Playwright is a capture tool, separate from the product dependencies.
If Playwright is installed outside this checkout, set `PLAYWRIGHT_MODULE` to
its absolute `index.mjs` path. To use an installed Google Chrome, also set
`PLAYWRIGHT_CHANNEL=chrome`.

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
  npm run demo:screenshots

PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
PLAYWRIGHT_CHANNEL=chrome \
  npm run demo:screenshots
```

The capture command serves only the built synthetic viewer on a temporary
loopback port. It checks the scope, evidence, report download, graph inspector,
search, and empty search state at 1440 × 1050. It also checks the main folio flow
at 390 × 844 for horizontal overflow. Browser errors and external requests
fail the run. The command replaces the four PNGs only after these checks pass.

The final build copies the new PNGs into the Pages artifact alongside
`index.html` and `tour.html`. The artifact check verifies that the tour images
match the source PNGs and that both pages contain no external assets or
live API calls. Open the captures to review layout before including them in a
pull request; automated checks do not judge visual quality.

## Preview locally

```sh
python3 -m http.server 8765 --bind 127.0.0.1 --directory graph/generated/pages-demo
```

Open `http://127.0.0.1:8765/` for the interactive viewer or
`http://127.0.0.1:8765/tour.html` for the screenshot tour. Stop the server with
Control-C. Building or previewing this directory does not publish it.

## What the screenshots show

| Image | State |
| --- | --- |
| `scope.png` | Source metadata, partial collection warning, and security questions |
| `evidence.png` | Fixture Notes, a modeled injection path, recorded permissions, and advice |
| `report.png` | Browser snapshot summary options, not a full Neo4j assessment report |
| `graph.png` | The graph workspace with Fixture Notes selected in the inspector |

The demo's observed and inferred labels describe the fictional dataset. They
are not findings about any real application or host.
