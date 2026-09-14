#!/usr/bin/env node
/** Capture the built synthetic viewer with an existing Playwright installation. */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { copyFile, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { tourSteps } from "./demo-tour.mjs";

const root = path.resolve(import.meta.dirname, "..");
const html = await readFile(path.join(root, "graph/generated/pages-demo/index.html"));
assert.ok(html.includes('data-rootstock-pages-demo="synthetic-graphite-laboratory-bench"'));
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const server = createServer((_request, response) => {
  response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  response.end(html);
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const temporary = await mkdtemp(path.join(tmpdir(), "rootstock-screenshots-"));
let browser;
const errors = [];

async function capture(page, name) {
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: path.join(temporary, name), animations: "disabled" });
}

async function assertNoOverflow(page) {
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
}

async function desktopFlow(page) {
  await page.goto(origin);
  assert.equal(await page.title(), "Rootstock - Synthetic static demo");
  await page.getByRole("heading", { name: "What needs investigation?" }).waitFor();
  await capture(page, "scope.png");
  await page.getByRole("button", { name: "Inspect snapshot", exact: true }).click();
  await page.getByRole("heading", { name: "Why can this app reach Full Disk Access?" }).waitFor();
  assert.ok(
    await page
      .getByRole("table")
      .innerText()
      .then((text) => text.includes("observed")),
  );
  await capture(page, "evidence.png");
  await page.getByRole("button", { name: "Prepare report", exact: true }).click();
  await page.getByRole("heading", { name: "Prepare a snapshot summary" }).waitFor();
  await capture(page, "report.png");
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Generate snapshot summary", exact: true }).click();
  const download = await downloadPromise;
  assert.equal(download.suggestedFilename(), "rootstock-snapshot-summary.md");
  const content = await readFile(await download.path(), "utf8");
  assert.match(content, /synthetic/);
  assert.match(content, /Fixture Notes/);
  await page.getByRole("button", { name: "Graph tools", exact: true }).click();
  await page.getByRole("button", { name: "Graph", exact: true }).click();
  await page.locator("#btn-zoom-fit").click();
  await page.locator("#node-list button").filter({ hasText: "Fixture Notes (synthetic)" }).click();
  await page.locator("#inspector").waitFor({ state: "visible" });
  await capture(page, "graph.png");
  await page.getByRole("searchbox", { name: "Search nodes", exact: true }).fill("no-such-fixture");
  await page.locator("#node-list-empty").waitFor({ state: "visible" });
  await page.getByRole("button", { name: "Clear search", exact: true }).click();
  await page.locator("#node-list-empty").waitFor({ state: "hidden" });
  await assertNoOverflow(page);
}

async function mobileFlow(page) {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(origin);
  await assertNoOverflow(page);
  await page.getByRole("button", { name: "Inspect snapshot", exact: true }).click();
  await page.getByRole("heading", { name: "Why can this app reach Full Disk Access?" }).waitFor();
  await assertNoOverflow(page);
  await page.getByRole("button", { name: "Prepare report", exact: true }).click();
  await page.getByRole("heading", { name: "Prepare a snapshot summary" }).waitFor();
  await assertNoOverflow(page);
}

try {
  browser = await chromium.launch({
    headless: true,
    ...(process.env.PLAYWRIGHT_CHANNEL ? { channel: process.env.PLAYWRIGHT_CHANNEL } : {}),
  });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1050 },
    deviceScaleFactor: 1,
    colorScheme: "dark",
    reducedMotion: "reduce",
    locale: "en-US",
    timezoneId: "UTC",
  });
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await page.route("**/*", (route) => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    errors.push("Unexpected network request outside the synthetic demo");
    return route.abort();
  });
  await desktopFlow(page);
  await mobileFlow(page);
  assert.deepEqual(errors, [], "Viewer must run without errors or external requests");
  const destination = path.join(root, "docs/assets/screenshots");
  await mkdir(destination, { recursive: true });
  for (const { file } of tourSteps) {
    await copyFile(path.join(temporary, file), path.join(destination, file));
  }
  console.log(
    "Captured four synthetic screens; desktop, mobile, search, and download checks passed.",
  );
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
  await rm(temporary, { recursive: true, force: true });
}
