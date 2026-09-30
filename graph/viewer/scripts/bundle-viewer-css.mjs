#!/usr/bin/env node
/**
 * Concatenate graph/viewer/css/* modules (per manifest.json) into the package viewer CSS resource.
 * Usage: node graph/viewer/scripts/bundle-viewer-css.mjs
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cssDir = join(root, "css");
const outPath =
  process.argv[2] ??
  join(root, "..", "src", "rootstock_graph", "resources", "viewer", "viewer.css");
const manifestPath = join(cssDir, "manifest.json");

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const files = Array.isArray(manifest.files) ? manifest.files : [];
if (files.length === 0) {
  console.error("bundle-viewer-css: manifest.json has no files[]");
  process.exit(1);
}

const header = [
  "/* Rootstock Graph Viewer CSS — assembled by graph/viewer/scripts/bundle-viewer-css.mjs */",
  "/* Source modules: graph/viewer/css/  |  rebuild: npm --prefix graph/viewer run bundle:css */",
  "/* Graphite Laboratory v2 */",
  "",
].join("\n");

const parts = [header];
for (const file of files) {
  const abs = join(cssDir, file);
  let body;
  try {
    body = readFileSync(abs, "utf8").replace(/\s+$/, "");
  } catch (err) {
    console.error(`bundle-viewer-css: missing module ${file}`);
    console.error(err);
    process.exit(1);
  }
  parts.push(`/* ===== ${file} ===== */`, body, "");
}

writeFileSync(outPath, `${parts.join("\n").trimEnd()}\n`, "utf8");
console.log(`bundle-viewer-css: wrote ${outPath} (${files.length} modules)`);
