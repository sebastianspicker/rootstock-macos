import assert from "node:assert/strict";

import {createViewerState, replaceGraphModel, safeNodeColor, shortestPath} from "../../graph/viewer-src/model.ts";
import {SpatialGrid} from "../../graph/viewer-src/spatial.ts";
import {propertyValue} from "../../graph/viewer-src/runtime.ts";
import {
  parseGraphPayload,
  parseOwnedList,
  parseQueryResult,
  queryResultMeta,
  parseTierResponse,
  resolveSameOriginApiTarget,
} from "../../graph/viewer-src/protocol.ts";

const payload = parseGraphPayload({
  metadata: {hostname: "fixture"},
  graph: {
    nodes: [
      {id: "a", kind: "rs_Application", properties: {}},
      {id: "b", kind: "rs_User", properties: {}},
    ],
    edges: [{source: "a", target: "b", kind: "rs_RELATES_TO", properties: {_traversable: true}}],
  },
});
const state = createViewerState(payload, false, "");
assert.deepEqual(shortestPath(state.graph, "a", "b")?.orderedNodeIds, ["a", "b"]);

const familyPayload = parseGraphPayload({
  metadata: {source_kind: "RootstockFamily", family_source: "mixed"},
  graph: {
    nodes: [
      {
        id: "rs-host-host-h1",
        kind: "rs_FamilyHost",
        label: "synthetic-macbook",
        properties: {_color: "#39c5cf", source: "rootstock-red", family_export: true},
      },
      {
        id: "rs-host-finding-red1",
        kind: "rs_RedFinding",
        label: "FDA permission pivot surface",
        properties: {
          _color: "#e05260",
          source: "rootstock-red",
          family_export: true,
          severity: "high",
        },
      },
      {
        id: "rs-host-finding-blue1",
        kind: "rs_BlueFinding",
        label: "SIP appears disabled",
        properties: {
          _color: "#58a6ff",
          source: "rootstock-blue",
          family_export: true,
          severity: "critical",
        },
      },
    ],
    edges: [
      {
        source: "rs-host-host-h1",
        target: "rs-host-finding-red1",
        kind: "rs_RedHasFinding",
        properties: {_traversable: false, source: "rootstock-red", family_export: true},
      },
      {
        source: "rs-host-host-h1",
        target: "rs-host-finding-blue1",
        kind: "rs_BlueHasFinding",
        properties: {_traversable: false, source: "rootstock-blue", family_export: true},
      },
    ],
  },
});
const familyState = createViewerState(familyPayload, false, "");
assert.equal(familyState.graph.kindMeta.has("rs_RedFinding"), true);
assert.equal(familyState.graph.kindMeta.has("rs_BlueFinding"), true);
assert.equal(familyState.graph.kindMeta.has("rs_FamilyHost"), true);
assert.equal(familyState.graph.edgeMeta.has("rs_RedHasFinding"), true);
assert.equal(familyState.graph.edgeMeta.has("rs_BlueHasFinding"), true);
assert.equal(familyState.graph.kindMeta.get("rs_RedFinding")?.count, 1);
assert.equal(familyState.graph.kindMeta.get("rs_BlueFinding")?.count, 1);
const redNode = familyState.graph.nodeById.get("rs-host-finding-red1");
const blueNode = familyState.graph.nodeById.get("rs-host-finding-blue1");
assert.equal(redNode?.properties.source, "rootstock-red");
assert.equal(blueNode?.properties.source, "rootstock-blue");
assert.equal(redNode?.kind, "rs_RedFinding");
assert.equal(blueNode?.kind, "rs_BlueFinding");

state.selection.selectedId = "a";
state.selection.pinnedId = "a";
state.selection.focusedId = "a";
replaceGraphModel(state, {
  graph: {nodes: [{id: "new", kind: "rs_Application", properties: {}}], edges: []},
});
assert.equal(state.selection.selectedId, null);
assert.equal(state.selection.pinnedId, null);
assert.equal(state.selection.focusedId, null);
assert.equal(state.graph.nodeById.has("a"), false);

assert.throws(() => parseGraphPayload({graph: {nodes: [], edges: [{}]}}), /Malformed graph response/);
assert.throws(() => parseGraphPayload({graph: {nodes: Array.from({length: 10_001}, (_, index) => ({id: String(index), kind: "rs_Node"})), edges: []}}), /Malformed graph response/);
assert.throws(() => parseGraphPayload({graph: {nodes: [], edges: Array.from({length: 50_001}, () => ({source: "a", target: "b", kind: "rs_RELATES_TO"}))}}), /Malformed graph response/);
assert.throws(() => parseQueryResult({rows: "not-an-array"}), /Malformed query response/);
assert.equal(parseQueryResult({rows: [], truncated: true}).truncated, true);
assert.equal(queryResultMeta(parseQueryResult({rows: [{id: "a"}], count: 1, truncated: true})), "Showing first 1 row (truncated)");
assert.equal(queryResultMeta(parseQueryResult({rows: [{id: "a"}]})), "1 row");
assert.equal(queryResultMeta(parseQueryResult({rows: []})), "0 rows");
assert.throws(() => parseQueryResult({rows: [{id: "a"}], count: 2}), /Malformed query response/);
assert.equal(resolveSameOriginApiTarget("/viewer", "/api/graph", "https://viewer.example"), "https://viewer.example/api/graph");
assert.throws(() => resolveSameOriginApiTarget("https://other.example", "/api/graph", "https://viewer.example"), /viewer origin/);
assert.throws(() => resolveSameOriginApiTarget("/viewer", "//other.example/api/graph", "https://viewer.example"), /viewer origin/);
assert.equal(propertyValue([[[[["deep"]]]]]), "[…]");
assert.equal(propertyValue("x".repeat(600)).length, 512);
assert.equal(propertyValue(Array.from({length: 21}, (_, index) => index)).endsWith(", …"), true);
assert.throws(() => parseTierResponse({tier0: 1, tier1: 1, tier2: 1, total: 2}), /Malformed tier response/);
assert.throws(() => parseOwnedList({owned: [], count: 1}), /Malformed owned response/);

assert.equal(safeNodeColor("#0a61c9"), "#0a61c9");
assert.equal(safeNodeColor("rgb(10, 97, 201)"), "rgb(10, 97, 201)");
assert.equal(safeNodeColor("hsl(210, 60%, 41%)"), "hsl(210, 60%, 41%)");
assert.equal(safeNodeColor("url(https://example.test/color.svg)"), "#8c99a8");
assert.equal(safeNodeColor("red; background: url(x)"), "#8c99a8");
assert.equal(safeNodeColor("rgb(999, 0, 0)"), "#8c99a8");

const displayed = new Map([["clustered", {x: 1_200, y: 1_100}]]);
const spatial = new SpatialGrid([{id: "clustered", x: 10, y: 20}], {
  positionFor: (node) => displayed.get(node.id) ?? node,
});
assert.equal(spatial.findNearest(1_200, 1_100, 1)?.id, "clustered");

process.stdout.write("viewer model/protocol checks passed\n");
