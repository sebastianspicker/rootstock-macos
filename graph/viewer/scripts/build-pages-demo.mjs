#!/usr/bin/env node

/**
 * Build the privacy-safe GitHub Pages demo from Rootstock's maintained viewer.
 *
 * The output is one self-contained HTML file. It uses the same template, CSS,
 * JavaScript bundle, and synthetic demo data.
 *
 * Usage:
 *   node graph/viewer/scripts/build-pages-demo.mjs
 *   node graph/viewer/scripts/build-pages-demo.mjs /path/to/index.html
 */

import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { demoGraph } from "./viewer-demo-data.mjs";
import { renderTour, tourSteps } from "./demo-tour.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const defaultOutput = path.join(repositoryRoot, "graph", "generated", "pages-demo", "index.html");

const demoCss = `
.demo-tour-link {
  color: var(--action, #b3d7ad);
  font: 13px/1.5 system-ui, sans-serif;
  white-space: nowrap;
  text-underline-offset: 4px;
}
.demo-tour-link:focus-visible { outline: 2px solid currentColor; outline-offset: 4px; }
.demo-disclosure {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
}
`;

function bootstrapScript() {
  const serializedGraph = JSON.stringify(demoGraph)
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
  return `
RootstockViewer.mount(${serializedGraph}, {mode: "static"});
document.getElementById("connection-status").textContent = "Static demo · synthetic data";
document.getElementById("connection-status").setAttribute("aria-label", "Static demo using synthetic data");
function addTourLink(parent) {
  const link = document.createElement("a");
  link.href = "tour.html";
  link.className = "demo-tour-link";
  link.textContent = "Screenshot tour";
  parent.append(link);
}
addTourLink(document.querySelector(".folio-topbar"));
addTourLink(document.querySelector(".status-group"));
new MutationObserver(() => {
  const header = document.querySelector(".folio-topbar");
  if (header && !header.querySelector(".demo-tour-link")) addTourLink(header);
}).observe(document.getElementById("evidence-folio"), {childList: true});
for (const id of ["nav-exports", "btn-export"]) {
  const action = document.getElementById(id);
  action.classList.add("demo-simulated-action");
  action.setAttribute("aria-label", "Export synthetic graph as PNG");
  action.setAttribute("title", "Downloads a PNG of the synthetic graph; no host command runs");
}
`;
}

function staticOnlyBundle(bundle) {
  return `const staticRequest = () => Promise.reject(new Error("Network access is disabled in this static demo."));\n${bundle
    .replaceAll("fetch(", "staticRequest(")
    .replaceAll("/api/", "/static-disabled/")}`;
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
  const viewerResources = path.join(
    repositoryRoot,
    "graph",
    "src",
    "rootstock_graph",
    "resources",
    "viewer",
  );
  const [template, css, bundle] = await Promise.all([
    readFile(path.join(viewerResources, "viewer_template.html"), "utf8"),
    readFile(path.join(viewerResources, "viewer.css"), "utf8"),
    readFile(path.join(viewerResources, "viewer.bundle.js"), "utf8"),
  ]);

  return template
    .replace("<head>", '<head>\n<link rel="icon" href="data:,">')
    .replace(
      '<html lang="en">',
      '<html lang="en" data-rootstock-pages-demo="synthetic-graphite-laboratory-bench">',
    )
    .replace("{{VIEWER_TITLE}}", "Synthetic static demo")
    .replace("{{VIEWER_CSS}}", `${css}\n${demoCss}`)
    .replace('<div id="app">', `<div id="app">${disclosureMarkup()}`)
    .replace("{{VIEWER_JS}}", staticOnlyBundle(bundle))
    .replace("{{VIEWER_BOOTSTRAP}}", bootstrapScript());
}

async function main() {
  const outputPath = path.resolve(process.argv[2] ?? defaultOutput);
  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, await renderDemo(), "utf8");
  const outputDirectory = path.dirname(outputPath);
  await writeFile(path.join(outputDirectory, "tour.html"), renderTour(), "utf8");
  await mkdir(path.join(outputDirectory, "screenshots"), { recursive: true });
  for (const step of tourSteps) {
    await copyFile(
      path.join(repositoryRoot, "docs/assets/screenshots", step.file),
      path.join(outputDirectory, "screenshots", step.file),
    );
  }
  console.log(`Built synthetic static demo: ${outputPath}`);
}

main().catch((error) => {
  console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
