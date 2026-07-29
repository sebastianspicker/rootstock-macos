# Public interface screenshots

The four PNG files in this directory are captures of the maintained Rootstock
viewer. The capture script mounts `graph/viewer_template.html`,
`graph/viewer.css`, and `graph/viewer.bundle.js` with the public seven-node
graph and provenance values from `scripts/release-screenshot-fixture.mjs`. It
does not read scan output or start an HTTP server.

| File | State shown |
|---|---|
| `viewer-overview.png` | Graphite Lab workspace: graph, node index, empty evidence rail |
| `viewer-node-inspector.png` | Full Disk Access selected in the evidence dossier |
| `viewer-attack-path.png` | Two-hop modeled path (Unsigned Helper → Shared Credential) with dossier open |
| `viewer-risk-filter.png` | Vulnerability and attack-path filters active |

These screenshots verify production viewer rendering and interactions with
synthetic data. They do not verify Neo4j connectivity, authenticated API
behavior, live query execution, or behavior on a real scan.

## Capture

Install the locked Node dependencies and Chromium, then run the capture:

```bash
npm ci --no-audit --no-fund --ignore-scripts
npx --no-install playwright install chromium
npm run screenshots:release
```

`ROOTSTOCK_BROWSER_PATH` may point to an existing Chromium executable when the
pinned Playwright browser is unavailable. Record that substitution with the
capture evidence.

`ROOTSTOCK_PLAYWRIGHT_PACKAGE` can select an existing Playwright package.

## Publication rules

- Keep the public fixture and production viewer capture states synchronized.
- Capture the maintained viewer through the script. Do not substitute
  hand-composed PNGs or unrelated placeholders.
- Review every PNG before publication for hostnames, usernames, paths, tokens,
  scan identifiers, package inventories, and desktop content.
- Do not commit browser traces, HAR files, ad hoc captures, or real host output.
- Keep intermediate captures under the ignored `generated/`, `raw/`, or
  `staging/` directories.

See [Frontend and report interface](../frontend.md) for the associated browser
verification requirements.
