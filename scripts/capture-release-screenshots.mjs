#!/usr/bin/env node

/**
 * Capture the public Rootstock interface gallery from the maintained viewer.
 *
 * This script never starts an HTTP server and never reads scan output. It mounts the
 * production template, stylesheet, and bundle with the deliberately synthetic
 * release fixture, then captures four stable states. Set ROOTSTOCK_PLAYWRIGHT_PACKAGE when Playwright is
 * not installed in this repository, and ROOTSTOCK_BROWSER_PATH to override the
 * system Chromium/Chrome discovery.
 *
 * Usage:
 *   node scripts/capture-release-screenshots.mjs
 *   ROOTSTOCK_PLAYWRIGHT_PACKAGE=/path/to/node_modules/playwright \
 *     node scripts/capture-release-screenshots.mjs
 */

import {access, mkdir, readFile} from "node:fs/promises";
import {constants as fsConstants} from "node:fs";
import path from "node:path";
import process from "node:process";
import {fileURLToPath, pathToFileURL} from "node:url";
import {
  fixture,
  RELEASE_SCREENSHOT_OUTPUTS,
  VIEWPORT,
} from "./release-screenshot-fixture.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outputDirectory = path.join(repositoryRoot, "docs", "screenshots");

async function main() {
  const playwright = await loadPlaywright();
  const viewerHtml = await renderViewer();
  await writeScreenshots(playwright, viewerHtml);
}

async function renderViewer() {
  const [template, css, bundle] = await Promise.all([
    readFile(path.join(repositoryRoot, "graph", "viewer_template.html"), "utf8"),
    readFile(path.join(repositoryRoot, "graph", "viewer.css"), "utf8"),
    readFile(path.join(repositoryRoot, "graph", "viewer.bundle.js"), "utf8"),
  ]);
  const bootstrap = `RootstockViewer.mount(${JSON.stringify(fixture)}, {mode:"static"});`;
  return template
    .replace("{{VIEWER_TITLE}}", "Synthetic release fixture")
    .replace("{{VIEWER_CSS}}", css)
    .replace("{{VIEWER_JS}}", bundle)
    .replace("{{VIEWER_BOOTSTRAP}}", bootstrap);
}

async function loadPlaywright() {
  const requestedPackage = process.env.ROOTSTOCK_PLAYWRIGHT_PACKAGE;
  try {
    let imported;
    if (requestedPackage) {
      imported = await import(pathToFileURL(path.join(path.resolve(requestedPackage), "index.js")).href);
    } else {
      imported = await import("playwright");
    }
    const playwright = imported.default ?? imported;
    if (!playwright.chromium) throw new Error("the loaded module does not expose chromium");
    return playwright;
  } catch (error) {
    const hint = requestedPackage
      ? `ROOTSTOCK_PLAYWRIGHT_PACKAGE=${requestedPackage}`
      : "ROOTSTOCK_PLAYWRIGHT_PACKAGE=/path/to/node_modules/playwright";
    throw new Error(`Playwright is unavailable. Install the locked development dependencies or rerun with ${hint}. Cause: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function writeScreenshots(playwright, viewerHtml) {
  const executablePath = await systemBrowserPath();
  let browser;
  try {
    browser = await playwright.chromium.launch({headless: true, ...(executablePath ? {executablePath} : {})});
  } catch (error) {
    const browser = executablePath ?? "Playwright's managed Chromium";
    throw new Error(`Could not launch ${browser}. Verify that the browser can run in this environment, or set ROOTSTOCK_BROWSER_PATH. Cause: ${error instanceof Error ? error.message : String(error)}`);
  }
  await ensureDirectory(outputDirectory);
  const context = await browser.newContext({colorScheme: "dark", reducedMotion: "reduce", viewport: VIEWPORT});
  const page = await context.newPage();
  const viewerUrl = "http://rootstock.invalid/";
  await page.route(viewerUrl, (route) => route.fulfill({
    body: viewerHtml,
    contentType: "text/html; charset=utf-8",
  }));
  try {
    await captureOverview(page, viewerUrl);
    await captureSelectedNode(page, viewerUrl);
    await capturePath(page, viewerUrl);
    await captureRiskFilter(page, viewerUrl);
  } finally {
    await context.close();
    await browser.close();
  }
}

async function captureOverview(page, viewerUrl) {
  await loadViewer(page, viewerUrl);
  await settlePage(page);
  await page.screenshot({
    animations: "disabled",
    caret: "hide",
    path: path.join(outputDirectory, RELEASE_SCREENSHOT_OUTPUTS.overview),
  });
}

async function captureSelectedNode(page, viewerUrl) {
  await loadViewer(page, viewerUrl);
  await page.getByRole("button", {name: /Full Disk Access/}).click();
  await page.getByRole("heading", {name: "Full Disk Access"}).waitFor();
  await settlePage(page);
  await page.screenshot({
    animations: "disabled",
    caret: "hide",
    path: path.join(outputDirectory, RELEASE_SCREENSHOT_OUTPUTS.inspector),
  });
}

async function capturePath(page, viewerUrl) {
  await loadViewer(page, viewerUrl);
  await page.locator("#btn-path").click();
  await page.getByRole("button", {name: /Unsigned Helper/}).click();
  await page.getByRole("button", {name: /Shared Credential/}).click();
  await page.getByText("2 hops", {exact: true}).waitFor();
  await page.getByRole("heading", {name: "Shared Credential"}).waitFor({state: "visible"});
  await settlePage(page);
  await page.screenshot({
    animations: "disabled",
    caret: "hide",
    path: path.join(outputDirectory, RELEASE_SCREENSHOT_OUTPUTS.path),
  });
}

async function captureRiskFilter(page, viewerUrl) {
  await loadViewer(page, viewerUrl);
  await page.getByRole("button", {name: "Vulnerable only"}).click();
  await page.getByRole("button", {name: "Attack paths"}).click();
  await settlePage(page);
  await page.screenshot({
    animations: "disabled",
    caret: "hide",
    path: path.join(outputDirectory, RELEASE_SCREENSHOT_OUTPUTS.risk),
  });
}

async function loadViewer(page, viewerUrl) {
  await page.goto(viewerUrl, {waitUntil: "load"});
  await page.getByRole("heading", {name: "Paths"}).waitFor();
  await page.locator("#graph-canvas").waitFor();
  await page.getByRole("button", {name: /Unsigned Helper/}).waitFor();
  await page.getByLabel("Theme").selectOption("dark");
}

async function settlePage(page) {
  await page.evaluate(() => {
    const activeElement = document.activeElement;
    if (activeElement && typeof activeElement.blur === "function") activeElement.blur();
  });
  await page.waitForTimeout(100);
}

async function ensureDirectory(directory) {
  await access(directory, fsConstants.F_OK).catch(async () => {
    await mkdir(directory, {recursive: true});
  });
}

async function systemBrowserPath() {
  if (process.env.ROOTSTOCK_BROWSER_PATH) return process.env.ROOTSTOCK_BROWSER_PATH;
  for (const candidate of [
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ]) {
    try {
      await access(candidate, fsConstants.X_OK);
      return candidate;
    } catch {
      // Try the next supported macOS browser before falling back to Playwright's browser lookup.
    }
  }
  return undefined;
}

main().catch((error) => {
  console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
