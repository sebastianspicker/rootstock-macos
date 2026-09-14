#!/usr/bin/env node
/** Compare a temporary rebuild with the current packaged assets, including uncommitted work. */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");
const temporary = mkdtempSync(join(tmpdir(), "rootstock-viewer-assets-"));
try {
  execFileSync(process.execPath, [
    join(root, "scripts/bundle-viewer-css.mjs"),
    join(temporary, "viewer.css"),
  ]);
  await build({
    entryPoints: [join(root, "graph/viewer-src/main.ts")],
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2022",
    minify: true,
    outfile: join(temporary, "viewer.bundle.js"),
  });
  for (const filename of ["viewer.css", "viewer.bundle.js"]) {
    const current = readFileSync(
      join(root, "graph/src/rootstock_graph/resources/viewer", filename),
    );
    if (!current.equals(readFileSync(join(temporary, filename))))
      throw new Error(`${filename} is stale; run npm run bundle`);
  }
  console.log("Packaged viewer assets match the working-tree sources.");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
