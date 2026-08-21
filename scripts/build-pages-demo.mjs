#!/usr/bin/env node

/**
 * Build the privacy-safe GitHub Pages demo from Rootstock's maintained viewer.
 *
 * The output is one self-contained HTML file. It uses the same template, CSS,
 * JavaScript bundle, and synthetic fixture as the public release screenshots.
 *
 * Usage:
 *   node scripts/build-pages-demo.mjs
 *   node scripts/build-pages-demo.mjs /path/to/index.html
 */

import {mkdir, readFile, writeFile} from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import {fileURLToPath} from "node:url";

import {fixture} from "./release-screenshot-fixture.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaultOutput = path.join(repositoryRoot, "graph", "generated", "pages-demo", "index.html");

const demoCss = `
.demo-disclosure {
  position: fixed;
  z-index: var(--z-status);
  right: 12px;
  bottom: 48px;
  max-width: min(560px, calc(100% - 24px));
  padding: 8px 12px;
  border: 1px solid var(--rule-strong);
  border-radius: var(--radius);
  background: var(--overlay);
  color: var(--muted);
  font-size: 11px;
  text-wrap: balance;
}
.demo-disclosure strong { color: var(--text); font-weight: 600; }
.demo-simulated-action::after {
  content: " · simulated";
  color: var(--path);
  font-size: 10px;
}
@media (max-width: 767px) {
  .demo-disclosure {
    right: 8px;
    bottom: 8px;
    max-width: calc(100% - 16px);
  }
}
@media print { .demo-disclosure { display: none !important; } }
`;

function bootstrapScript() {
  return `
RootstockViewer.mount(${JSON.stringify(fixture)}, {mode: "static"});
document.getElementById("connection-status").textContent = "Static demo · synthetic fixture";
document.getElementById("connection-status").setAttribute("aria-label", "Static demo using a synthetic fixture");
for (const id of ["nav-exports", "btn-export"]) {
  const action = document.getElementById(id);
  action.classList.add("demo-simulated-action");
  action.setAttribute("aria-label", "Export simulated fixture as PNG");
  action.setAttribute("title", "Downloads a PNG of the simulated fixture; no host command runs");
}
`;
}

function disclosureMarkup() {
  return `
  <aside class="demo-disclosure" aria-label="Static demo disclosure">
    <strong>Synthetic static demo.</strong>
    No host collection, server connection, query execution, or graph mutation occurs here.
  </aside>
`;
}

async function renderDemo() {
  const [template, css, bundle] = await Promise.all([
    readFile(path.join(repositoryRoot, "graph", "viewer_template.html"), "utf8"),
    readFile(path.join(repositoryRoot, "graph", "viewer.css"), "utf8"),
    readFile(path.join(repositoryRoot, "graph", "viewer.bundle.js"), "utf8"),
  ]);

  return template
    .replace("{{VIEWER_TITLE}}", "Synthetic static demo")
    .replace("{{VIEWER_CSS}}", `${css}\n${demoCss}`)
    .replace("<div id=\"app\">", `<div id=\"app\">${disclosureMarkup()}`)
    .replace("{{VIEWER_JS}}", bundle)
    .replace("{{VIEWER_BOOTSTRAP}}", bootstrapScript());
}

async function main() {
  const outputPath = path.resolve(process.argv[2] ?? defaultOutput);
  await mkdir(path.dirname(outputPath), {recursive: true});
  await writeFile(outputPath, await renderDemo(), "utf8");
  console.log(`Built synthetic static demo: ${outputPath}`);
}

main().catch((error) => {
  console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
