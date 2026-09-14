import test from "node:test";
import assert from "node:assert/strict";
import { SpatialGrid } from "../viewer-src/spatial";
import { around, intersects, textWidth } from "../viewer-src/canvas-cache";
import { createViewerState, shortestPath } from "../viewer-src/model";
import { orderedNodes, NODE_PAGE_SIZE } from "../viewer-src/node-list";

test("incremental drag crosses cells, keeps visibility current and tie ordering stable", () => {
  const a = { id: "a", x: 10, y: 10 }, b = { id: "b", x: 10, y: 10 };
  const visible = new Set(["a", "b"]);
  const grid = new SpatialGrid([b, a], { isVisible: (node) => visible.has(node.id) });
  assert.equal(grid.findNearest(10, 10, 0), a);
  a.x = -500;
  grid.update(a);
  assert.equal(grid.findNearest(10, 10, 0), b);
  assert.equal(grid.findNearest(-500, 10, 0), a);
  visible.delete("a");
  assert.equal(grid.findNearest(-500, 10, 0), null);
  visible.add("a");
  assert.equal(grid.findNearest(-500, 10, 0), a);
});

test("updates read only the changed position", () => {
  let calls = 0;
  const nodes = Array.from({ length: 10_000 }, (_, i) => ({ id: String(i), x: i, y: i }));
  const grid = new SpatialGrid(nodes, { positionFor: (node) => { calls++; return node; } });
  calls = 0;
  nodes[0].x = -1000;
  grid.update(nodes[0]);
  assert.equal(calls, 1);
});

test("culling includes touching boundaries and offscreen endpoints spanning the viewport", () => {
  const viewport = { left: 0, top: 0, right: 100, bottom: 100 };
  assert.ok(intersects(viewport, around(-10, 50, 10)));
  assert.ok(intersects(viewport, { left: -1000, top: 49, right: 1000, bottom: 51 }));
  assert.ok(!intersects(viewport, around(-11, 50, 10)));
});

test("text measurements are cached by font and text", () => {
  let calls = 0;
  const context = { font: "", measureText: () => { calls++; return { width: 40, actualBoundingBoxLeft: 0, actualBoundingBoxRight: 40 }; } } as unknown as CanvasRenderingContext2D;
  assert.equal(textWidth(context, "16px sans-serif", "same"), 40);
  textWidth(context, "16px sans-serif", "same");
  assert.equal(calls, 1);
  textWidth(context, "12px sans-serif", "same");
  assert.equal(calls, 2);
});

test("graph label order is cached without changing modeled paths", () => {
  const payload = { graph: { nodes: [
    { id: "b", kind: "rs_User", label: "Beta", properties: {} },
    { id: "a", kind: "rs_User", label: "Alpha", properties: {} },
  ], edges: [{ source: "a", target: "b", kind: "rs_Test", properties: { _traversable: true } }] } };
  const { graph } = createViewerState(payload, false, "");
  const path = shortestPath(graph, "a", "b");
  assert.equal(orderedNodes(graph), orderedNodes(graph));
  assert.deepEqual(orderedNodes(graph).map((node) => node.id), ["a", "b"]);
  assert.deepEqual(shortestPath(graph, "a", "b"), path);
  assert.equal(NODE_PAGE_SIZE, 200);
});

test("pagination resets on filtering and refresh, reveals selection, and retains unchanged rows", async () => {
  const { TestElement, installDom } = await import("./dom");
  const { renderNodeList, resetNodeList } = await import("../viewer-src/node-list");
  const { renderPathWorkspace } = await import("../viewer-src/paths");
  installDom();
  const payload = { graph: { nodes: Array.from({length:405}, (_, i) => ({id: String(i).padStart(3, "0"), kind:"rs_User", properties:{}})), edges:[] } };
  const state = createViewerState(payload, false, "");
  state.render.visibleNodeIds = new Set(state.graph.nodes.map(node => node.id));
  const dom = { nodeList: new TestElement("ul"), nodeListCount: new TestElement(), nodeListEmpty: new TestElement(), pathSource: new TestElement("select"), pathDestination: new TestElement("select"), pathStatus: new TestElement() };
  const controller = { state, dom, actions: {} } as unknown as import("../viewer-src/runtime").Controller;
  resetNodeList(controller);
  assert.equal(dom.nodeList.children.length, 200);
  const controls = dom.nodeList.adjacent!;
  controls.children[2]!.click();
  assert.equal(controls.children[1]!.textContent, "201–400 of 405");
  const row = dom.nodeList.children[0];
  state.selection.selectedId = "201";
  renderNodeList(controller);
  assert.equal(dom.nodeList.children[0], row);
  assert.equal(dom.nodeList.querySelectorAll().filter(button => button.getAttribute("aria-current") === "true").length, 1);
  state.selection.selectedId = "404";
  renderNodeList(controller);
  assert.equal(dom.nodeList.children.length, 5);
  state.render.visibleNodeIds = new Set(["001"]);
  resetNodeList(controller);
  assert.equal(controls.children[1]!.textContent, "1–1 of 1");
  state.render.visibleNodeIds.clear();
  resetNodeList(controller);
  assert.equal(dom.nodeList.children.length, 0);
  assert.equal(dom.nodeListEmpty.hidden, false);
  renderPathWorkspace(controller);
  const option = dom.pathSource.children[1];
  renderPathWorkspace(controller);
  assert.equal(dom.pathSource.children[1], option);
  state.graph = createViewerState({graph:{nodes:[],edges:[]}},false,"").graph;
  renderPathWorkspace(controller);
  renderNodeList(controller);
  assert.equal(dom.pathSource.children.length, 1);
  assert.equal(controls.children[1]!.textContent, "0–0 of 0");
});

test("hit testing includes a node radius across a cell boundary", () => {
  const node = {id:"wide",x:127,y:0};
  const grid = new SpatialGrid([node], {radiusFor: () => 70});
  assert.equal(grid.findNearest(60,0,0),node);
});

// Evidence folio uses the public OpenGraph spelling and keeps installation identities distinct.
import { coverageText, injectableApps, localResult, matchApplication, recommendations, scopeMetadata, shortestFdaPath, snapshotSummary } from "../viewer-src/folio-data";
import { reportContent, validFilename } from "../viewer-src/folio-report";

function folioFixture() {
  return createViewerState({ metadata: { generated_at: "2026-01-02T00:00:00Z" }, graph: {
    nodes: [
      { id: "attacker", kind: "rs_Application", properties: { bundle_id: "attacker.payload" } },
      { id: "app-one", kind: "rs_Application", properties: { name: "Synthetic Notes", bundle_id: "example.notes", path: "/Applications/Synthetic Notes.app" } },
      { id: "app-two", kind: "rs_Application", properties: { name: "Synthetic Notes", bundle_id: "example.notes", path: "/Applications/Other/Synthetic Notes.app" } },
      { id: "permission", kind: "rs_TCCPermission", properties: { service: "kTCCServiceSystemPolicyAllFiles" } },
      { id: "recommendation", kind: "rs_Recommendation", properties: { key: "harden", text: "Review hardening", priority: "critical" } },
      { id: "computer", kind: "rs_Computer", properties: { name: "synthetic-host", scanned_at: "2026-01-01T00:00:00Z", collection_error_count: 1, collection_error_sources: ["keychain"], import_status: "partial" } },
    ], edges: [
      { source: "attacker", target: "app-one", kind: "rs_CanInjectInto", properties: { inferred: true } },
      { source: "app-one", target: "permission", kind: "rs_HasTCCGrant", properties: { allowed: true } },
      { source: "app-two", target: "permission", kind: "rs_HasTCCGrant", properties: { allowed: false } },
      { source: "app-one", target: "recommendation", kind: "rs_HasRecommendation" },
    ],
  } }, false).graph;
}

test("folio snapshot analysis recognizes OpenGraph relationships and requires an allowed grant", () => {
  const graph = folioFixture();
  assert.deepEqual(injectableApps(graph).map(node => node.id), ["app-one"]);
  graph.edges[1].properties.allowed = false;
  assert.equal(injectableApps(graph).length, 0);
  delete graph.edges[1].properties.allowed;
  assert.equal(injectableApps(graph).length, 0);
});

test("folio result inspection distinguishes duplicate bundle IDs by path", () => {
  const graph = folioFixture();
  assert.equal(matchApplication(graph, { bundle_id: "example.notes" }), undefined);
  assert.equal(matchApplication(graph, { bundle_id: "example.notes", path: "/Applications/Other/Synthetic Notes.app" })?.id, "app-two");
});

test("folio scope retains partial coverage and uses collected time rather than export time", () => {
  const graph = folioFixture();
  assert.match(coverageText(graph), /keychain.*Partial coverage/);
  assert.equal(scopeMetadata(graph).collected, "2026-01-01T00:00:00Z");
  graph.nodes.find(node => node.id === "computer").properties = {};
  assert.equal(scopeMetadata(graph).collected, "Unknown");
  assert.match(coverageText(graph), /coverage unknown/);
});

test("folio local path and recommendation questions inspect snapshot relationships", () => {
  const graph = folioFixture();
  assert.deepEqual(shortestFdaPath(graph).map(node => node.id), ["attacker", "app-one", "permission"]);
  assert.equal(recommendations(graph, "app-two").length, 0);
  assert.equal(localResult(graph, "100").rows[0].affected_apps, 1);
  assert.equal(localResult(graph, "02").rows[0].path_length, 2);
  assert.match(snapshotSummary(graph), /not a full Neo4j assessment report/);
});

test("folio report response and browser filename validation reject invalid inputs", () => {
  assert.equal(reportContent({ content: "# Assessment", media_type: "text/markdown" }), "# Assessment");
  assert.throws(() => reportContent({ content: 42, media_type: "text/html" }));
  assert.throws(() => reportContent({ content: "text" }));
  for (const filename of ["", " ", "../report.md", "a\\report.md", "report\n.md"]) assert.equal(validFilename(filename), false);
  assert.equal(validFilename("synthetic-assessment.md"), true);
});

test("folio resolves source kind and Computer hostname, and numeric skipped grants stay visible", () => {
  const graph = folioFixture();
  const computer = graph.nodes.find(node => node.id === "computer");
  computer.properties.hostname = "synthetic-collector-host";
  computer.properties.tcc_grants_skipped = 3;
  assert.equal(scopeMetadata(graph).host, "synthetic-collector-host");
  assert.equal(scopeMetadata(graph).source, "Collector scan");
  assert.match(coverageText(graph), /3 TCC grants skipped/);
  graph.payload.metadata.source_kind = "synthetic-public-demo";
  assert.equal(scopeMetadata(graph).source, "synthetic-public-demo");
});

test("folio exports preserve full installation identifiers", () => {
  const graph = folioFixture();
  const path = `/Applications/${"synthetic-".repeat(80)}Notes.app`;
  graph.nodes.find(node => node.id === "app-one").properties.path = path;
  assert.ok(snapshotSummary(graph).includes(path));
  assert.equal(matchApplication(graph, { bundle_id: "example.notes", path })?.id, "app-one");
});
