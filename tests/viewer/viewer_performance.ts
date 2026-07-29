import assert from "node:assert/strict";
import {performance} from "node:perf_hooks";

import {computeVisibility, createViewerState, nodeRadius} from "../../graph/viewer-src/model.ts";
import {SpatialGrid} from "../../graph/viewer-src/spatial.ts";
import type {GraphPayload} from "../../graph/viewer-src/types.ts";

const nodes = Array.from({length: 10_000}, (_, index) => ({
  id: `n${index}`,
  x: (index * 73) % 10_000,
  y: (index * 191) % 10_000,
  kind: index % 3 === 0 ? "rs_Application" : "rs_User",
  label: `Synthetic node ${index}`,
  properties: {},
}));
const edges = Array.from({length: 50_000}, (_, index) => ({
  source: `n${index % nodes.length}`,
  target: `n${(index * 17 + 3) % nodes.length}`,
  kind: "rs_RELATES_TO",
  properties: {_traversable: true},
}));
const payload: GraphPayload = {graph: {nodes, edges}};
const state = createViewerState(payload, false, "");
const visibleNodeIds = new Set(nodes.map((node) => node.id));
const index = new SpatialGrid(state.graph.nodes, {
  isVisible: (node) => visibleNodeIds.has(node.id),
  radiusFor: (node) => nodeRadius(state.graph, node.id),
});

const nestedHits = new SpatialGrid([
  {id: "a", x: 0, y: 0},
  {id: "z", x: 0, y: 0},
], {radiusFor: () => 8});
assert.equal(nestedHits.findNearest(0, 0, 20)?.id, "a",
  "overlapping clickable nodes use a deterministic ID tie-break");

const nearestBoundary = new SpatialGrid([
  {id: "near-center", x: 3, y: 0},
  {id: "near-boundary", x: 10, y: 0},
], {radiusFor: (node) => node.id === "near-center" ? 1 : 9.5});
assert.equal(nearestBoundary.findNearest(0, 0, 20)?.id, "near-boundary",
  "hit testing chooses the nearest clickable boundary, not the nearest center");

const hitDurations: number[] = [];
for (let sample = 0; sample < 2_000; sample += 1) {
  const started = performance.now();
  index.findNearest((sample * 97) % 10_000, (sample * 211) % 10_000, 20);
  hitDurations.push(performance.now() - started);
}

const filterDurations: number[] = [];
for (let sample = 0; sample < 20; sample += 1) {
  state.filters.searchTerm = sample % 2 ? "synthetic node 9" : "";
  const started = performance.now();
  computeVisibility(state);
  filterDurations.push(performance.now() - started);
}

function percentile(values: readonly number[], fraction: number): number {
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.floor((ordered.length - 1) * fraction)] ?? Number.POSITIVE_INFINITY;
}

const result = {
  fixture: {nodes: nodes.length, edges: edges.length},
  hitTestP95Ms: percentile(hitDurations, 0.95),
  filterP95Ms: percentile(filterDurations, 0.95),
};
assert.ok(result.hitTestP95Ms < 16, JSON.stringify(result));
assert.ok(result.filterP95Ms < 100, JSON.stringify(result));
process.stdout.write(`${JSON.stringify(result)}\n`);
