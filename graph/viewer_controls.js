/* global H, SpatialGrid, W, activeNodeKinds, closeInspector */
/* global computeVisibility, drawNodeShape, edgeKinds, el, exitFocusMode */
/* global exitPathMode, focusNodeId, getNodeShape, kindMeta, links, markDirty */
/* global nodeById, nodeRadius, nodes, pathMode, togglePathMode */
/* global updateAccessibleNodeList, visibleLinkSet, visibleNodeIds */
/* global attackPathMode:writable, clusterByType:writable, searchTerm:writable */
/* global showLabels:writable, spatialIndex:writable, transform:writable */
/* exported exportPNG, toggleClustering, toggleVulnFilter */
/* exported spatialIndex */

// ── Controls ────────────────────────────────────────────────────────────────
function resetZoom() {
  // Fit all visible nodes
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  nodes.forEach(n => {
    if (!visibleNodeIds.has(n.id)) return;
    minX = Math.min(minX, n.x);
    minY = Math.min(minY, n.y);
    maxX = Math.max(maxX, n.x);
    maxY = Math.max(maxY, n.y);
  });
  if (!isFinite(minX)) { transform = {x: 0, y: 0, k: 1}; markDirty(); return; }
  const pad = 80;
  const gw = maxX - minX + pad * 2;
  const gh = maxY - minY + pad * 2;
  const k = Math.min(W / gw, H / gh, 2);
  transform = {
    x: W / 2 - (minX + maxX) / 2 * k,
    y: H / 2 - (minY + maxY) / 2 * k,
    k: k
  };
  markDirty();
}

function toggleLabels() {
  showLabels = !showLabels;
  document.getElementById('btn-labels').classList.toggle('active', showLabels);
  document.getElementById('btn-labels').setAttribute('aria-pressed', String(showLabels));
  markDirty();
}

function toggleAttackPaths() {
  attackPathMode = !attackPathMode;
  document.getElementById('btn-attack').classList.toggle('active', attackPathMode);
  document.getElementById('btn-attack').setAttribute('aria-pressed', String(attackPathMode));
  computeVisibility(); markDirty();
}

function toggleClustering() {
  clusterByType = !clusterByType;
  document.getElementById('btn-cluster').classList.toggle('active', clusterByType);
  document.getElementById('btn-cluster').setAttribute('aria-pressed', String(clusterByType));

  if (clusterByType) {
    const kinds = [...kindMeta.keys()];
    const r = 600;
    kinds.forEach((kind, ki) => {
      const angle = 2 * Math.PI * ki / kinds.length;
      const cx = 1000 + Math.cos(angle) * r;
      const cy = 1000 + Math.sin(angle) * r;
      nodes.forEach((n, j) => {
        if (n.kind === kind) {
          const a2 = 2 * Math.PI * j / nodes.length;
          n.x = cx + Math.cos(a2) * 80 + deterministicJitter(n.id, 17);
          n.y = cy + Math.sin(a2) * 80 + deterministicJitter(n.id, 31);
        }
      });
    });
  }
  spatialIndex = new SpatialGrid(nodes);
  // Re-fit view
  resetZoom();
}

function deterministicJitter(value, salt) {
  let hash = salt;
  for (const character of String(value)) hash = (hash * 33 + character.charCodeAt(0)) >>> 0;
  return (hash / (2 ** 32 - 1) - 0.5) * 40;
}

let vulnFilterActive = false;
function toggleVulnFilter() {
  vulnFilterActive = !vulnFilterActive;
  document.getElementById('btn-vuln').classList.toggle('active', vulnFilterActive);
  document.getElementById('btn-vuln').setAttribute('aria-pressed', String(vulnFilterActive));
  if (vulnFilterActive) {
    // Show only nodes that have AFFECTED_BY edges (or are Vulnerability nodes)
    const vulnNodeIds = new Set();
    links.forEach(l => {
      if (l.kind === 'rs_AffectedBy') {
        vulnNodeIds.add(l.source);
        vulnNodeIds.add(l.target);
      }
    });
    visibleNodeIds.clear();
    vulnNodeIds.forEach(id => visibleNodeIds.add(id));
    // Also show edges between visible nodes
    visibleLinkSet.clear();
    links.forEach((l, i) => {
      if (visibleNodeIds.has(l.source) && visibleNodeIds.has(l.target)) visibleLinkSet.add(i);
    });
  } else {
    computeVisibility();
  }
  updateAccessibleNodeList();
  markDirty();
}

function exportPNG() {
  const exportCanvas = document.createElement('canvas');
  const scale = 2;
  exportCanvas.width = W * scale;
  exportCanvas.height = H * scale;
  const ectx = exportCanvas.getContext('2d');
  ectx.fillStyle = '#0d1117';
  ectx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);

  // Draw at current transform
  ectx.translate(transform.x * scale, transform.y * scale);
  ectx.scale(transform.k * scale, transform.k * scale);

  // Draw edges
  links.forEach((l, i) => {
    if (!visibleLinkSet.has(i)) return;
    const src = nodeById.get(l.source);
    const tgt = nodeById.get(l.target);
    if (!src || !tgt) return;
    const trav = l.properties?._traversable;
    ectx.beginPath();
    ectx.moveTo(src.x, src.y);
    ectx.lineTo(tgt.x, tgt.y);
    ectx.strokeStyle = trav ? '#58a6ff' : '#30363d';
    ectx.globalAlpha = trav ? 0.5 : 0.2;
    ectx.lineWidth = trav ? 1.5 : 0.7;
    ectx.stroke();
  });

  ectx.globalAlpha = 1;

  // Draw nodes with shapes
  nodes.forEach(n => {
    if (!visibleNodeIds.has(n.id)) return;
    const r = nodeRadius(n);
    const color = n.properties?._color || kindMeta.get(n.kind)?.color || '#8b949e';
    const shape = getNodeShape(n.kind);
    ectx.beginPath();
    drawNodeShape(ectx, n.x, n.y, r, shape);
    ectx.fillStyle = color;
    ectx.fill();
    ectx.strokeStyle = '#21262d';
    ectx.lineWidth = 1.5;
    ectx.stroke();
    if (n.label) {
      ectx.font = '500 10px -apple-system, sans-serif';
      ectx.textAlign = 'center';
      ectx.textBaseline = 'top';
      ectx.fillStyle = '#c9d1d9';
      ectx.fillText(n.label.length > 24 ? n.label.slice(0, 23) + '\u2026' : n.label, n.x, n.y + r + 4);
    }
  });

  // Watermark
  ectx.setTransform(scale, 0, 0, scale, 0, 0);
  ectx.globalAlpha = 0.3;
  ectx.font = '500 11px -apple-system, sans-serif';
  ectx.textAlign = 'right';
  ectx.fillStyle = '#8b949e';
  ectx.fillText('Rootstock Attack Graph', W - 16, H - 12);
  ectx.globalAlpha = 1;

  exportCanvas.toBlob(blob => {
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'rootstock-graph.png'; a.click();
    URL.revokeObjectURL(url);
  }, 'image/png');
}

// ── Keyboard shortcuts ──────────────────────────────────────────────────────
function isTextEntryActive() {
  return ['INPUT', 'TEXTAREA'].includes(document.activeElement?.tagName);
}

function handleEscapeKey(isInput) {
  if (pathMode) {
    exitPathMode();
    return;
  }
  if (focusNodeId) {
    exitFocusMode();
    return;
  }
  if (document.getElementById('inspector').classList.contains('open')) {
    closeInspector();
    return;
  }
  if (searchTerm) {
    document.getElementById('search').value = '';
    searchTerm = '';
    computeVisibility();
    markDirty();
    return;
  }
  if (isInput) document.activeElement.blur();
}

function handleSearchShortcut(event) {
  if (!(event.ctrlKey || event.metaKey) || event.key !== 'f') return false;
  event.preventDefault();
  document.getElementById('search').focus();
  return true;
}

const KEYBOARD_ACTIONS = new Map([
  ['p', togglePathMode],
  ['a', toggleAttackPaths],
  ['l', toggleLabels],
  ['r', resetZoom],
]);

function toggleNumberedKind(key) {
  const number = Number.parseInt(key);
  if (number < 1 || number > 9) return;
  const kinds = [...kindMeta.keys()].sort((a, b) => kindMeta.get(b).count - kindMeta.get(a).count);
  const kind = kinds[number - 1];
  if (!kind) return;
  const checkbox = document.querySelector('#node-filters input[data-kind="' + kind + '"]');
  if (!checkbox) return;
  checkbox.checked = !checkbox.checked;
  if (checkbox.checked) activeNodeKinds.add(kind);
  else activeNodeKinds.delete(kind);
  computeVisibility();
  markDirty();
}

function handleGlobalKeydown(event) {
  const isInput = isTextEntryActive();
  if (handleSearchShortcut(event)) return;
  if (event.key === 'Escape') {
    handleEscapeKey(isInput);
    return;
  }
  if (isInput) return;
  const action = KEYBOARD_ACTIONS.get(event.key);
  if (action) action();
  else toggleNumberedKind(event.key);
}

document.addEventListener('keydown', handleGlobalKeydown);

// ── Initial setup ───────────────────────────────────────────────────────────
computeVisibility();
// Fit to visible nodes on load
setTimeout(resetZoom, 50);

// Stats - build a rich stats bar
const statsEl = document.getElementById('stats');

function addStatItem(color, text) {
  const item = el('span', {className: 'stat-item'});
  if (color) {
    const dot = el('span', {className: 'stat-dot'});
    dot.style.background = color;
    item.appendChild(dot);
  }
  item.appendChild(el('span', {textContent: text}));
  statsEl.appendChild(item);
}

function updateStats() {
  const attackEdgeCount = [...edgeKinds.values()].filter(e => e.traversable).reduce((s,e) => s + e.count, 0);
  const ownedCount = nodes.filter(n => n.properties?.owned).length;
  const criticalNodes = nodes.filter(n => n.properties?.risk_level === 'critical').length;
  const highRiskNodes = nodes.filter(n => n.properties?.risk_level === 'high').length;
  const tier0Count = nodes.filter(n => n.properties?.tier === 0).length;
  const injectableCount = nodes.filter(n => n.properties?.injectable).length;

  statsEl.textContent = '';
  addStatItem('#8b949e', nodes.length + ' nodes');
  addStatItem('#30363d', links.length + ' edges');
  addStatItem('#58a6ff', attackEdgeCount + ' attack');
  if (criticalNodes > 0) addStatItem('#f85149', criticalNodes + ' critical');
  if (highRiskNodes > 0) addStatItem('#d29922', highRiskNodes + ' high');
  if (tier0Count > 0) addStatItem('#f85149', tier0Count + ' T0');
  if (injectableCount > 0) addStatItem('#ff7b72', injectableCount + ' injectable');
  if (ownedCount > 0) addStatItem('#ffd700', ownedCount + ' owned');
}
updateStats();

// ── Risk posture summary chips ────────────────────────────────────────────
const riskSummaryEl = document.getElementById('risk-summary');
function addRiskChip(level, count) {
  if (count === 0) return;
  const chip = el('span', {className: 'risk-chip ' + level});
  chip.appendChild(el('span', {className: 'chip-count', textContent: String(count)}));
  chip.appendChild(el('span', {textContent: level.charAt(0).toUpperCase() + level.slice(1)}));
  riskSummaryEl.appendChild(chip);
}

function updateRiskSummary() {
  const criticalNodes = nodes.filter(n => n.properties?.risk_level === 'critical').length;
  const highRiskNodes = nodes.filter(n => n.properties?.risk_level === 'high').length;
  const mediumNodes = nodes.filter(n => n.properties?.risk_level === 'medium').length;
  const lowNodes = nodes.filter(n => n.properties?.risk_level === 'low').length;
  riskSummaryEl.textContent = '';
  addRiskChip('critical', criticalNodes);
  addRiskChip('high', highRiskNodes);
  addRiskChip('medium', mediumNodes);
  addRiskChip('low', lowNodes);
  // If no risk data, show a placeholder
  if (criticalNodes + highRiskNodes + mediumNodes + lowNodes === 0) {
    riskSummaryEl.appendChild(el('span', {textContent: 'No risk scores computed',
      className: 'risk-chip'}));
  }
}
updateRiskSummary();
