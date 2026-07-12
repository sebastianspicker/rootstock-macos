const assert = require('node:assert/strict');
const {performance} = require('node:perf_hooks');

const nodes = Array.from({length: 10000}, (_, index) => ({
  id: `n${index}`,
  x: (index * 73) % 10000,
  y: (index * 191) % 10000,
  kind: index % 3 === 0 ? 'rs_Application' : 'rs_User',
  label: `Synthetic node ${index}`,
}));
const visibleNodeIds = new Set(nodes.map(node => node.id));
const nodeRadius = () => 8;
global.nodes = nodes;
global.visibleNodeIds = visibleNodeIds;
global.nodeRadius = nodeRadius;
const {SpatialGrid} = require('../../graph/viewer_spatial.js');

const index = new SpatialGrid(nodes, {isVisible: node => visibleNodeIds.has(node.id), radiusFor: nodeRadius});
const hitDurations = [];
for (let sample = 0; sample < 2000; sample++) {
  const started = performance.now();
  index.findNearest((sample * 97) % 10000, (sample * 211) % 10000, 20);
  hitDurations.push(performance.now() - started);
}

const edges = Array.from({length: 50000}, (_, index) => ({
  source: `n${index % nodes.length}`,
  target: `n${(index * 17 + 3) % nodes.length}`,
}));
const searchTextById = new Map(nodes.map(node => [node.id, node.label.toLowerCase()]));
const filterDurations = [];
for (let sample = 0; sample < 20; sample++) {
  const started = performance.now();
  const term = sample % 2 ? 'synthetic node 9' : '';
  const visible = new Set();
  for (const node of nodes) {
    if (!term || searchTextById.get(node.id).includes(term)) visible.add(node.id);
  }
  let visibleEdges = 0;
  for (const edge of edges) {
    if (visible.has(edge.source) && visible.has(edge.target)) visibleEdges++;
  }
  assert.ok(visibleEdges >= 0);
  filterDurations.push(performance.now() - started);
}

function percentile(values, fraction) {
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.floor((ordered.length - 1) * fraction)];
}

const result = {
  fixture: {nodes: nodes.length, edges: edges.length},
  hitTestP95Ms: percentile(hitDurations, 0.95),
  filterP95Ms: percentile(filterDurations, 0.95),
};
assert.ok(result.hitTestP95Ms < 16, JSON.stringify(result));
assert.ok(result.filterP95Ms < 100, JSON.stringify(result));
process.stdout.write(`${JSON.stringify(result)}\n`);
