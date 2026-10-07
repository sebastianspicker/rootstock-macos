/** esbuild options for the packaged viewer bundle, shared by the build and the freshness check. */
import { join } from "node:path";

const root = join(import.meta.dirname, "..");

export function viewerBundleOptions(outfile) {
  return {
    entryPoints: [join(root, "src/main.ts")],
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2022",
    minify: true,
    outfile,
  };
}

export const packagedBundlePath = join(
  root,
  "../src/rootstock_graph/resources/viewer/viewer.bundle.js",
);
