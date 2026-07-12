/* global SpatialGrid, centerOnNode, closeInspector, drawFrame, handlePathClick */
/* global hideContextMenu, hideTooltip, inspectNode, showContextMenu */
/* global showTooltip, updateRiskSummary, updateStats */
/* global spatialIndex:writable */
/* exported clusterByType, ctx, dirty, nodeRadius, pathSource, pathTarget */
/* exported propRow, replaceGraphData, sectionHeader, showLabels */

// ── Data (with pre-computed x,y positions) ──────────────────────────────────
let DATA = null /* VIEWER_DATA */;
const nodes = DATA.graph.nodes;
const edges = DATA.graph.edges;

// Build lookup
const nodeById = new Map(nodes.map(n => [n.id, n]));
// Resolve valid links
const links = edges.filter(e => nodeById.has(e.source) && nodeById.has(e.target));

// ── Safe DOM helpers ────────────────────────────────────────────────────────
function el(tag, attrs, children) {
  const e = document.createElement(tag);
  if (attrs) Object.entries(attrs).forEach(([k, v]) => {
    if (k === 'className') e.className = v;
    else if (k === 'textContent') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  });
  if (children) children.forEach(c => { if (c) e.appendChild(c); });
  return e;
}

function propRow(key, value) {
  const row = el('div', {className: 'prop-row'});
  row.appendChild(el('span', {className: 'prop-key', textContent: String(key)}));
  let cls = 'prop-val';
  let display;
  if (typeof value === 'boolean') {
    cls += value ? ' bool-true' : ' bool-false';
    display = value ? 'true' : 'false';
  } else if (Array.isArray(value)) {
    display = value.join(', ') || '(empty)';
  } else if (value === null || value === undefined) {
    cls += ' bool-false'; display = '(null)';
  } else { display = String(value); }
  row.appendChild(el('span', {className: cls, textContent: display}));
  return row;
}

function sectionHeader(text) {
  const h = el('h4', {textContent: text});
  return el('div', {className: 'prop-section'}, [h]);
}

// ── Derived data ────────────────────────────────────────────────────────────
const degreeMap = new Map();
links.forEach(l => {
  degreeMap.set(l.source, (degreeMap.get(l.source) || 0) + 1);
  degreeMap.set(l.target, (degreeMap.get(l.target) || 0) + 1);
});

function searchableNodeText(node) {
  return [
    node.label,
    node.properties?.bundle_id,
    node.properties?.name,
    node.properties?.service,
  ].filter(Boolean).join('\n').toLowerCase();
}

const searchTextById = new Map(nodes.map(node => [node.id, searchableNodeText(node)]));

function nodeRadius(d) {
  const degree = degreeMap.get(d.id) || 0;
  return Math.min(4 + Math.sqrt(degree) * 3, 24);
}

// Node kinds with colors
const kindMeta = new Map();
nodes.forEach(n => {
  if (!kindMeta.has(n.kind)) {
    kindMeta.set(n.kind, {
      color: n.properties?._color || '#888',
      count: 0,
      label: n.kind.replace('rs_', '').replace(/([A-Z])/g, ' $1').trim()
    });
  }
  kindMeta.get(n.kind).count++;
});

// Edge kinds
const edgeKinds = new Map();
links.forEach(l => {
  if (!edgeKinds.has(l.kind)) {
    edgeKinds.set(l.kind, {
      label: l.kind.replace('rs_', '').replace(/([A-Z])/g, ' $1').trim(),
      traversable: l.properties?._traversable ?? false,
      count: 0
    });
  }
  edgeKinds.get(l.kind).count++;
});

// Adjacency lists for fast neighbor lookup
const adjOut = new Map();  // source -> [{target, link}]
const adjIn = new Map();   // target -> [{source, link}]
links.forEach(l => {
  if (!adjOut.has(l.source)) adjOut.set(l.source, []);
  adjOut.get(l.source).push({target: l.target, link: l});
  if (!adjIn.has(l.target)) adjIn.set(l.target, []);
  adjIn.get(l.target).push({source: l.source, link: l});
});

// ── Progressive disclosure: default visibility ──────────────────────────────
// Only Applications visible on first load; others can be toggled on
const DEFAULT_VISIBLE_KINDS = new Set(['Application', 'rs_Application']);

// ── State ───────────────────────────────────────────────────────────────────
let showLabels = true;
let attackPathMode = false;
const activeNodeKinds = new Set(DEFAULT_VISIBLE_KINDS);
const activeEdgeKinds = new Set(edgeKinds.keys());
let selectedNode = null;
let searchTerm = '';
let hoverNode = null;
let pinnedNode = null;  // Click to pin neighbor highlight
let focusNodeId = null;
let pathMode = false;
let pathSource = null;
let pathTarget = null;
let pathResult = null;
let clusterByType = false;
let dragNode = null;
let dirty = true;
let didDrag = false;  // Suppress click after pan/drag
let mouseDownPos = {x: 0, y: 0};

function rebuildDerivedData(resetFilters = false) {
  nodeById.clear();
  nodes.forEach(n => nodeById.set(n.id, n));

  searchTextById.clear();
  nodes.forEach(node => searchTextById.set(node.id, searchableNodeText(node)));

  links.splice(0, links.length, ...edges.filter(e => nodeById.has(e.source) && nodeById.has(e.target)));

  degreeMap.clear();
  links.forEach(l => {
    degreeMap.set(l.source, (degreeMap.get(l.source) || 0) + 1);
    degreeMap.set(l.target, (degreeMap.get(l.target) || 0) + 1);
  });

  kindMeta.clear();
  nodes.forEach(n => {
    if (!kindMeta.has(n.kind)) {
      kindMeta.set(n.kind, {
        color: n.properties?._color || '#888',
        count: 0,
        label: n.kind.replace('rs_', '').replace(/([A-Z])/g, ' $1').trim()
      });
    }
    kindMeta.get(n.kind).count++;
  });

  edgeKinds.clear();
  links.forEach(l => {
    if (!edgeKinds.has(l.kind)) {
      edgeKinds.set(l.kind, {
        label: l.kind.replace('rs_', '').replace(/([A-Z])/g, ' $1').trim(),
        traversable: l.properties?._traversable ?? false,
        count: 0
      });
    }
    edgeKinds.get(l.kind).count++;
  });

  adjOut.clear();
  adjIn.clear();
  links.forEach(l => {
    if (!adjOut.has(l.source)) adjOut.set(l.source, []);
    adjOut.get(l.source).push({target: l.target, link: l});
    if (!adjIn.has(l.target)) adjIn.set(l.target, []);
    adjIn.get(l.target).push({source: l.source, link: l});
  });

  if (resetFilters) {
    activeEdgeKinds.clear();
    edgeKinds.forEach((_info, kind) => activeEdgeKinds.add(kind));
    if (![...activeNodeKinds].some(kind => kindMeta.has(kind))) {
      activeNodeKinds.clear();
      DEFAULT_VISIBLE_KINDS.forEach(kind => {
        if (kindMeta.has(kind)) activeNodeKinds.add(kind);
      });
    }
    buildFilters();
  }

  document.getElementById('node-count').textContent = nodes.length;
  document.getElementById('edge-count').textContent = links.length;
  const currentMeta = DATA.metadata || {};
  document.getElementById('meta-info').textContent =
    [currentMeta.hostname, currentMeta.generated_at?.split('T')[0]].filter(Boolean).join(' \u2014 ');
  computeVisibility();
  if (typeof updateStats === 'function') updateStats();
  if (typeof updateRiskSummary === 'function') updateRiskSummary();
  if (typeof spatialIndex !== 'undefined') spatialIndex = new SpatialGrid(nodes);
  markDirty();
}

function replaceGraphData(data) {
  DATA = data;
  nodes.splice(0, nodes.length, ...(data.graph?.nodes || []));
  edges.splice(0, edges.length, ...(data.graph?.edges || []));
  rebuildDerivedData(true);
}

// Transform state (pan/zoom)
let transform = {x: 0, y: 0, k: 1};

// ── Visibility computation ──────────────────────────────────────────────────
let visibleNodeIds = new Set();
let visibleLinkSet = new Set();

function computeVisibility() {
  // Path result takes priority
  if (pathMode && pathResult) {
    visibleNodeIds = pathResult.nodeIds;
    visibleLinkSet = new Set();
    links.forEach((l, i) => {
      if (pathResult.linkKeys.has(linkKey(l))) visibleLinkSet.add(i);
    });
    updateAccessibleNodeList();
    return;
  }

  // Focus mode: node + 1-hop neighbors
  if (focusNodeId) {
    visibleNodeIds = new Set([focusNodeId]);
    visibleLinkSet = new Set();
    links.forEach((l, i) => {
      if (l.source === focusNodeId || l.target === focusNodeId) {
        visibleNodeIds.add(l.source);
        visibleNodeIds.add(l.target);
        visibleLinkSet.add(i);
      }
    });
    updateAccessibleNodeList();
    return;
  }

  // Normal: kind filter + search filter
  visibleNodeIds = new Set();
  nodes.forEach(n => {
    const kindOk = activeNodeKinds.has(n.kind);
    const searchOk = !searchTerm || searchTextById.get(n.id)?.includes(searchTerm);
    if (kindOk && searchOk) visibleNodeIds.add(n.id);
  });

  visibleLinkSet = new Set();
  links.forEach((l, i) => {
    if (!visibleNodeIds.has(l.source) || !visibleNodeIds.has(l.target)) return;
    if (!activeEdgeKinds.has(l.kind)) return;
    if (attackPathMode && !l.properties?._traversable) return;
    visibleLinkSet.add(i);
  });
  updateAccessibleNodeList();
}

let frameRequested = false;
function markDirty() {
  dirty = true;
  if (!frameRequested) {
    frameRequested = true;
    requestAnimationFrame(drawFrame);
  }
}

function linkKey(l) { return l.source + '>' + l.kind + '>' + l.target; }

// ── Metadata ────────────────────────────────────────────────────────────────
const meta = DATA.metadata || {};
document.getElementById('meta-info').textContent =
  [meta.hostname, meta.generated_at?.split('T')[0]].filter(Boolean).join(' \u2014 ');
document.getElementById('node-count').textContent = nodes.length;
document.getElementById('edge-count').textContent = links.length;

// ── Filters ─────────────────────────────────────────────────────────────────
function buildFilters() {
  const nf = document.getElementById('node-filters');
  nf.textContent = '';
  [...kindMeta.entries()].sort((a,b) => b[1].count - a[1].count).forEach(([kind, info]) => {
    const cb = el('input', {type: 'checkbox', 'data-kind': kind});
    cb.checked = activeNodeKinds.has(kind);
    cb.addEventListener('change', e => {
      if (e.target.checked) activeNodeKinds.add(kind);
      else activeNodeKinds.delete(kind);
      computeVisibility(); markDirty();
    });
    const dot = el('span', {className: 'color-dot'});
    dot.style.background = info.color;
    nf.appendChild(el('label', {className: 'filter-item'}, [
      cb, dot,
      el('span', {textContent: info.label}),
      el('span', {className: 'filter-count', textContent: String(info.count)})
    ]));
  });

  const ef = document.getElementById('edge-filters');
  ef.textContent = '';
  const travCount = [...edgeKinds.values()].filter(e => e.traversable).reduce((s,e) => s + e.count, 0);
  const nonTravCount = [...edgeKinds.values()].filter(e => !e.traversable).reduce((s,e) => s + e.count, 0);

  const travCb = el('input', {type: 'checkbox', id: 'filter-trav'});
  travCb.checked = true;
  travCb.addEventListener('change', e => {
    edgeKinds.forEach((info, kind) => {
      if (info.traversable) {
        if (e.target.checked) activeEdgeKinds.add(kind);
        else activeEdgeKinds.delete(kind);
      }
    });
    computeVisibility(); markDirty();
  });
  ef.appendChild(el('label', {className: 'filter-item'}, [
    travCb, el('span', {textContent: 'Traversable (attack)'}),
    el('span', {className: 'filter-count', textContent: String(travCount)})
  ]));

  const nonTravCb = el('input', {type: 'checkbox', id: 'filter-nontrav'});
  nonTravCb.checked = true;
  nonTravCb.addEventListener('change', e => {
    edgeKinds.forEach((info, kind) => {
      if (!info.traversable) {
        if (e.target.checked) activeEdgeKinds.add(kind);
        else activeEdgeKinds.delete(kind);
      }
    });
    computeVisibility(); markDirty();
  });
  ef.appendChild(el('label', {className: 'filter-item'}, [
    nonTravCb, el('span', {textContent: 'Non-traversable (info)'}),
    el('span', {className: 'filter-count', textContent: String(nonTravCount)})
  ]));
}
buildFilters();

function updateAccessibleNodeList() {
  const list = document.getElementById('node-list');
  if (!list) return;
  const visible = pathMode && !pathResult
    ? nodes
    : nodes.filter(node => visibleNodeIds.has(node.id));
  list.textContent = '';
  const fragment = document.createDocumentFragment();
  visible.forEach(node => {
    const info = kindMeta.get(node.kind) || {};
    const button = el('button', {
      type: 'button',
      className: 'node-list-button',
      'aria-current': selectedNode?.id === node.id ? 'true' : 'false',
      onclick: () => {
        if (pathMode) handlePathClick(node);
        else {
          selectedNode = node;
          pinnedNode = node;
          inspectNode(node);
          centerOnNode(node);
        }
        updateAccessibleNodeList();
      }
    }, [
      el('span', {className: 'color-dot', 'aria-hidden': 'true'}),
      el('span', {className: 'node-list-label', textContent: node.label || node.id}),
      el('span', {className: 'node-list-kind', textContent: info.label || node.kind})
    ]);
    button.querySelector('.color-dot').style.background = info.color || '#8c99a8';
    fragment.appendChild(el('li', null, [button]));
  });
  list.appendChild(fragment);
  document.getElementById('node-list-count').textContent = visible.length + ' visible';
  document.getElementById('node-list-empty').hidden = visible.length !== 0;
  const status = document.getElementById('search-status');
  if (nodes.length === 0) status.textContent = 'The graph is empty.';
  else if (visible.length === 0) status.textContent = 'No nodes match the current search and filters.';
  else status.textContent = visible.length + ' of ' + nodes.length + ' nodes visible.';
}

// ── Search ──────────────────────────────────────────────────────────────────
document.getElementById('search').addEventListener('input', e => {
  searchTerm = e.target.value.toLowerCase();
  computeVisibility(); markDirty();
});

// ── Canvas setup ────────────────────────────────────────────────────────────
const container = document.getElementById('graph-container');
const canvas = document.getElementById('graph-canvas');
const ctx = canvas.getContext('2d');
let W, H, dpr;

function resizeCanvas() {
  dpr = window.devicePixelRatio || 1;
  W = container.clientWidth;
  H = container.clientHeight;
  canvas.width = W * dpr;
  canvas.height = H * dpr;
  canvas.style.width = W + 'px';
  canvas.style.height = H + 'px';
  markDirty();
}
resizeCanvas();
window.addEventListener('resize', resizeCanvas);
if ('ResizeObserver' in window) new ResizeObserver(resizeCanvas).observe(container);

// ── Transform helpers ───────────────────────────────────────────────────────
function screenToWorld(sx, sy) {
  return {
    x: (sx - transform.x) / transform.k,
    y: (sy - transform.y) / transform.k
  };
}

// ── Pan & Zoom (mouse/trackpad) ─────────────────────────────────────────────
let isPanning = false;
let panStart = {x: 0, y: 0};

canvas.addEventListener('wheel', e => {
  e.preventDefault();
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;

  // Zoom around mouse position
  const zoomFactor = e.deltaY > 0 ? 0.92 : 1.08;
  const newK = Math.max(0.05, Math.min(20, transform.k * zoomFactor));
  const ratio = newK / transform.k;
  transform.x = mx - (mx - transform.x) * ratio;
  transform.y = my - (my - transform.y) * ratio;
  transform.k = newK;
  markDirty();
}, {passive: false});

canvas.addEventListener('mousedown', e => {
  if (e.button === 2) return; // right-click handled separately
  didDrag = false;
  mouseDownPos = {x: e.clientX, y: e.clientY};
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const world = screenToWorld(mx, my);

  // Check if clicking a node
  const hit = spatialIndex.findNearest(world.x, world.y, 20 / transform.k);
  if (hit) {
    dragNode = hit;
    dragNode._dragOffsetX = world.x - hit.x;
    dragNode._dragOffsetY = world.y - hit.y;
    canvas.style.cursor = 'grabbing';
  } else {
    isPanning = true;
    panStart = {x: e.clientX - transform.x, y: e.clientY - transform.y};
    canvas.style.cursor = 'grabbing';
  }
});

function detectPointerDrag(event) {
  if (!didDrag && (dragNode || isPanning)) {
    const dx = event.clientX - mouseDownPos.x;
    const dy = event.clientY - mouseDownPos.y;
    if (dx * dx + dy * dy > 16) didDrag = true;
  }
}

function moveDraggedNode(x, y) {
  const world = screenToWorld(x, y);
  dragNode.x = world.x - dragNode._dragOffsetX;
  dragNode.y = world.y - dragNode._dragOffsetY;
  markDirty();
}

function movePannedCanvas(event) {
  transform.x = event.clientX - panStart.x;
  transform.y = event.clientY - panStart.y;
  markDirty();
}

function updateHoveredNode(event, x, y) {
  const world = screenToWorld(x, y);
  const hit = spatialIndex.findNearest(world.x, world.y, 20 / transform.k);
  if (hit !== hoverNode) {
    hoverNode = hit;
    canvas.style.cursor = hit ? 'pointer' : 'default';
    if (hit) showTooltip(event, hit);
    else hideTooltip();
    markDirty();
  } else if (hit) {
    const tooltip = document.getElementById('tooltip');
    tooltip.style.left = (x + 16) + 'px';
    tooltip.style.top = (y - 8) + 'px';
  }
}

canvas.addEventListener('mousemove', event => {
  const rect = canvas.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  detectPointerDrag(event);
  if (dragNode) return moveDraggedNode(x, y);
  if (isPanning) return movePannedCanvas(event);
  updateHoveredNode(event, x, y);
});

canvas.addEventListener('mouseup', () => {
  if (dragNode) {
    // If barely moved, treat as click
    dragNode = null;
    spatialIndex = new SpatialGrid(nodes);
    canvas.style.cursor = 'default';
    markDirty();
    return;
  }
  if (isPanning) {
    isPanning = false;
    canvas.style.cursor = 'default';
  }
});

canvas.addEventListener('click', e => {
  // Ignore click if it was actually a pan/drag
  if (didDrag) return;

  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const world = screenToWorld(mx, my);
  const hit = spatialIndex.findNearest(world.x, world.y, 20 / transform.k);

  hideContextMenu();

  if (hit) {
    if (pathMode) { handlePathClick(hit); return; }
    // Toggle pin: click same node unpins, different node re-pins
    if (pinnedNode && pinnedNode.id === hit.id) {
      pinnedNode = null;
      selectedNode = null;
      closeInspector();
    } else {
      pinnedNode = hit;
      selectedNode = hit;
      inspectNode(hit);
    }
  } else {
    if (pathMode) return;
    pinnedNode = null;
    selectedNode = null;
    closeInspector();
  }
  markDirty();
});

canvas.addEventListener('contextmenu', e => {
  e.preventDefault();
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const world = screenToWorld(mx, my);
  const hit = spatialIndex.findNearest(world.x, world.y, 20 / transform.k);
  if (hit) showContextMenu(e, hit);
});
