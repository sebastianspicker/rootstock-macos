#!/usr/bin/env node
/** Bundle TypeScript logic tests with the existing esbuild and run Node's test runner. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { build } from "esbuild";

const temporary = mkdtempSync(join(tmpdir(), "rootstock-viewer-tests-"));
try {
  const outfile = join(temporary, "logic.test.mjs");
  await build({
    entryPoints: [resolve(import.meta.dirname, "../graph/viewer-tests/logic.test.ts")],
    bundle: true,
    platform: "node",
    format: "esm",
    outfile,
  });
  execFileSync(process.execPath, ["--test", outfile], { stdio: "inherit" });
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
