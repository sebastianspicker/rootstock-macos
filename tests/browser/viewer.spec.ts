import http, {type IncomingMessage, type ServerResponse} from "node:http";
import {type AddressInfo} from "node:net";
import fs from "node:fs";

import AxeBuilder from "@axe-core/playwright";
import {expect, test, type Page} from "@playwright/test";
import {deterministicClusterOffset} from "../../graph/viewer-src/model";

const graph = {
  metadata: {
    hostname: "synthetic-browser-fixture",
    generated_at: "2026-07-11T00:00:00Z",
    collected_at: "2026-07-10T23:59:32Z",
    imported_at: "2026-07-10T23:59:46Z",
    derived_at: "2026-07-10T23:59:55Z",
    source: "browser-fixture",
  },
  graph: {
    nodes: [
      {id: "app", kind: "rs_Application", label: "Demo App", x: 200, y: 180, properties: {bundle_id: "com.example.demo", _color: "#0a61c9", evidence: "synthetic fixture", risk_level: "high"}},
      {id: "fda", kind: "rs_TCCPermission", label: "Full Disk Access", x: 420, y: 180, properties: {_color: "#bd2432", evidence: "synthetic fixture", risk_level: "critical"}},
    ],
    edges: [{source: "app", target: "fda", kind: "rs_HAS_TCC_GRANT", properties: {_traversable: true}}],
  },
};

function assembledViewer(live: boolean): string {
  const script = fs.readFileSync("graph/viewer.bundle.js", "utf8");
  const payload = live ? {metadata: {}, graph: {nodes: [], edges: []}} : graph;
  return fs.readFileSync("graph/viewer_template.html", "utf8")
    .replace("{{VIEWER_TITLE}}", live ? "Live fixture" : "Static fixture")
    .replace("{{VIEWER_CSS}}", fs.readFileSync("graph/viewer.css", "utf8"))
    .replace("{{VIEWER_JS}}", script)
    .replace("{{VIEWER_BOOTSTRAP}}", `RootstockViewer.mount(${JSON.stringify(payload)}, ${JSON.stringify(live ? {mode: "live"} : {mode: "static"})});`);
}

const apiPayloads = new Map<string, unknown>([
  ["/api/queries", [
    {id: "01", name: "Fixture query", purpose: "Browser result fixture", category: "Blue Team", severity: "Informational"},
  ]],
  ["/api/queries/01/run", {rows: [{name: "Demo App"}], count: 1}],
  ["/api/owned", {owned: [], count: 0}],
]);
let server: http.Server;
let origin = "";

function hasFixtureToken(request: IncomingMessage): boolean {
  return request.headers.authorization === "Bearer browser-fixture-token";
}

function serveFixtureApi(request: IncomingMessage, response: ServerResponse): void {
  response.setHeader("Content-Type", "application/json");
  if (request.url === "/api/graph") {
    response.end(JSON.stringify(graph));
    return;
  }
  const payload = apiPayloads.get(request.url ?? "");
  if (payload !== undefined) {
    response.end(JSON.stringify(payload));
    return;
  }
  response.writeHead(404);
  response.end(JSON.stringify({detail: "Not found"}));
}

function handleFixtureRequest(request: IncomingMessage, response: ServerResponse): void {
  if (request.url === "/static" || request.url === "/live") {
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    response.end(assembledViewer(request.url === "/live"));
    return;
  }
  if (!hasFixtureToken(request)) {
    response.writeHead(401, {"Content-Type": "application/json"});
    response.end(JSON.stringify({detail: "Missing or invalid bearer token"}));
    return;
  }
  serveFixtureApi(request, response);
}

test.beforeAll(async () => {
  server = http.createServer(handleFixtureRequest);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

test.afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
});

async function expectNoSeriousAxeFindings(page: Page): Promise<void> {
  const result = await new AxeBuilder({page}).analyze();
  expect(result.violations.filter((item) => item.impact === "serious" || item.impact === "critical")).toEqual([]);
}

async function connect(page: Page): Promise<void> {
  await page.goto(`${origin}/live`);
  await connectOpenPage(page);
}

async function connectOpenPage(page: Page): Promise<void> {
  await page.getByLabel("API token").fill("browser-fixture-token");
  await page.getByRole("button", {name: "Connect"}).click();
  await expect(page.getByText("Live · connected")).toBeVisible();
  await expect(page.getByRole("button", {name: /Demo App/})).toBeVisible();
}

async function buildFixturePath(page: Page, app: ReturnType<Page["getByRole"]>): Promise<void> {
  await page.locator("#btn-path").click();
  await app.click();
  await page.getByRole("button", {name: /Full Disk Access/}).click();
  await expect(page.getByText("1 hop", {exact: true})).toBeVisible();
}

function graphResponse(hostname: string, id: string, label: string, x: number, y: number): object {
  return {
    metadata: {hostname},
    graph: {nodes: [{id, kind: "rs_Application", label, x, y, properties: {}}], edges: []},
  };
}

test("static graph supports keyboard selection, path building, and theme override", async ({page}) => {
  await page.goto(`${origin}/static`);
  const app = page.getByRole("button", {name: /Demo App/});
  await expect(app).toBeVisible();
  await app.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", {name: "Demo App"})).toBeVisible();
  await expectNoSeriousAxeFindings(page);
  await buildFixturePath(page, app);
  await page.getByLabel("Theme").selectOption("dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expectNoSeriousAxeFindings(page);
});

test("workstation shell exposes payload-backed metrics, provenance, and inspector tabs", async ({page}) => {
  await page.goto(`${origin}/static`);
  const workspaceTitle = page.getByRole("heading", {name: "Paths", includeHidden: true});
  await expect(workspaceTitle).toHaveCount(1);
  if (test.info().project.name !== "narrow") await expect(workspaceTitle).toBeVisible();
  await expect(page.getByRole("navigation", {name: "Primary workspace"})).toBeVisible();
  await expect(page.getByRole("region", {name: "Risk posture"})).toContainText("100%");
  await expect(page.getByRole("contentinfo", {name: "Graph provenance timeline"})).toContainText("Snapshot");
  await page.getByRole("button", {name: /Demo App/}).click();
  await page.getByRole("tab", {name: "Relations"}).click();
  await expect(page.getByText("Relationship summary")).toBeVisible();
  await expect(page.getByText("Incoming")).toBeVisible();
  await page.getByRole("button", {name: "Queries", exact: true}).first().click();
  await expect(page.getByRole("heading", {name: "Saved queries"})).toBeVisible();
});

test("clustered canvas nodes remain selectable at their displayed positions", async ({page}) => {
  await page.goto(`${origin}/static`);
  await page.getByRole("button", {name: "Labels", exact: true}).click();
  await page.getByRole("button", {name: "Cluster"}).click();
  const canvas = page.locator("#graph-canvas");
  await canvas.scrollIntoViewIfNeeded();
  const box = await canvas.boundingBox();
  if (!box) throw new Error("Expected graph canvas bounds");

  const app = {
    x: 1_000 + 240 + 57 + deterministicClusterOffset("app") * 0.25,
    y: 1_000 + deterministicClusterOffset("app:y") * 0.25,
  };
  const permission = {
    x: 1_000 - 240 + 57 + deterministicClusterOffset("fda") * 0.25,
    y: 1_000 + deterministicClusterOffset("fda:y") * 0.25,
  };
  const minX = Math.min(app.x, permission.x) - 7;
  const maxX = Math.max(app.x, permission.x) + 7;
  const minY = Math.min(app.y, permission.y) - 7;
  const maxY = Math.max(app.y, permission.y) + 7;
  const k = Math.min(2, Math.max(0.08, Math.min(
    (box.width - 112) / (maxX - minX),
    (box.height - 112) / Math.max(1, maxY - minY),
  )));
  const x = box.x + box.width / 2 + (app.x - (minX + maxX) / 2) * k;
  const y = box.y + box.height / 2 + (app.y - (minY + maxY) / 2) * k;
  await page.mouse.click(x, y);
  await expect(page.getByRole("heading", {name: "Demo App"})).toBeVisible();
});

test("live viewer uses an inline session-only token gate", async ({page}) => {
  await page.goto(`${origin}/live`);
  await expect(page.getByRole("heading", {name: "Connect to this Rootstock session"})).toBeVisible();
  await expectNoSeriousAxeFindings(page);
  await connectOpenPage(page);
  await page.getByRole("tab", {name: "Queries"}).click();
  await page.getByRole("button", {name: /Fixture query/}).click();
  await expect(page.getByRole("heading", {name: /Fixture query/})).toBeVisible();
  await expect(page.getByRole("button", {name: "Highlight node"})).toBeVisible();
  await expectNoSeriousAxeFindings(page);
});

test("live refresh clears interaction state from the graph it replaces", async ({page}) => {
  await connect(page);
  const app = page.getByRole("button", {name: /Demo App/});
  await page.getByRole("button", {name: "Cluster"}).click();
  await page.getByRole("button", {name: "Vulnerable only"}).click();
  await expect(page.locator("#btn-cluster")).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("#btn-vuln")).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", {name: "Refresh graph"}).click();
  await expect(page.locator("#btn-cluster")).toHaveAttribute("aria-pressed", "false");
  await expect(page.locator("#btn-vuln")).toHaveAttribute("aria-pressed", "false");
  await expect(app).toBeVisible();

  await app.click();
  await page.getByRole("button", {name: "Focus neighborhood"}).click();
  await expect(page.locator("#focus-banner")).toHaveClass(/visible/);
  await page.getByRole("button", {name: "Refresh graph"}).click();
  await expect(page.locator("#focus-banner")).not.toHaveClass(/visible/);
  await expect(page.locator("#inspector")).not.toHaveClass(/open/);
  await expect(page.locator("[aria-current=\"true\"]")).toHaveCount(0);

  await buildFixturePath(page, app);
  await expect(page.locator("#path-banner")).toHaveClass(/visible/);
  await page.getByRole("button", {name: "Refresh graph"}).click();
  await expect(page.locator("#path-banner")).not.toHaveClass(/visible/);
  await expect(page.locator("#detail-empty")).toBeVisible();
});

test("live refresh keeps the newest graph when responses finish out of order", async ({page}) => {
  await connect(page);
  const pendingGraphRoutes: import("@playwright/test").Route[] = [];
  await page.route("**/api/graph", (route) => pendingGraphRoutes.push(route));
  const refresh = page.getByRole("button", {name: "Refresh graph"});
  await refresh.click();
  await refresh.click();
  await expect.poll(() => pendingGraphRoutes.length).toBe(2);

  const olderResponse = pendingGraphRoutes.shift();
  const newerResponse = pendingGraphRoutes.shift();
  if (!olderResponse || !newerResponse) throw new Error("Expected two pending graph routes");
  await newerResponse.fulfill({json: graphResponse("newer-graph", "newer", "Newer App", 300, 200)});
  await expect(page.getByRole("button", {name: /Newer App/})).toBeVisible();
  await olderResponse.fulfill({json: graphResponse("older-graph", "older", "Older App", 100, 100)});
  await expect(page.getByRole("button", {name: /Newer App/})).toBeVisible();
  await expect(page.getByRole("button", {name: /Older App/})).toHaveCount(0);
  await expect(page.locator("#live-status")).toHaveText("Graph refreshed.");
});

test("narrow layout does not create page-level horizontal clipping", async ({page}) => {
  test.skip(test.info().project.name !== "narrow");
  await page.goto(`${origin}/static`);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await expect(page.getByRole("tab", {name: "Queries"})).toBeVisible();
  await expect(page.getByLabel("Theme")).toBeVisible();
  expect(await page.getByLabel("Theme").evaluate((element) => element.getBoundingClientRect().height)).toBeGreaterThanOrEqual(44);
});
