/* global H, W, activeEdgeKinds, adjIn, adjOut, computeVisibility, container */
/* global edgeKinds, el, kindMeta, linkKey, markDirty, nodeById, propRow */
/* global sectionHeader */
/* global selectedNode:writable, transform:writable */
/* global focusNodeId:writable, pathMode:writable, pathResult:writable */
/* global pathSource:writable, pathTarget:writable */
/* exported closeInspector, handlePathClick, showContextMenu, togglePathMode */
/* exported selectedNode, transform */

// ── BFS shortest path ───────────────────────────────────────────────────────
function findPathParents(sourceId, targetId) {
  const visited = new Set([sourceId]);
  const parent = new Map();
  const queue = [sourceId];
  while (queue.length > 0) {
    const current = queue.shift();
    if (current === targetId) return parent;
    for (const {target, link} of adjOut.get(current) || []) {
      const traversable = activeEdgeKinds.has(link.kind) && link.properties?._traversable;
      if (!traversable || visited.has(target)) continue;
      visited.add(target);
      parent.set(target, {from: current, link});
      queue.push(target);
    }
  }
  return null;
}

function reconstructPath(parent, sourceId, targetId) {
  const nodeIds = new Set();
  const linkKeys = new Set();
  const hops = [];
  let cur = targetId;
  while (parent.has(cur)) {
    const {from, link} = parent.get(cur);
    nodeIds.add(cur);
    linkKeys.add(linkKey(link));
    hops.unshift({from, to: cur, edge: link});
    cur = from;
  }
  nodeIds.add(sourceId);
  return {nodeIds, linkKeys, hops};
}

function bfsShortestPath(sourceId, targetId) {
  const parent = findPathParents(sourceId, targetId);
  return parent ? reconstructPath(parent, sourceId, targetId) : null;
}

// ── Path mode ───────────────────────────────────────────────────────────────
function togglePathMode() {
  if (pathMode) { exitPathMode(); return; }
  exitFocusMode();
  pathMode = true; pathSource = null; pathTarget = null; pathResult = null;
  document.getElementById('btn-path').classList.add('active');
  document.getElementById('btn-path').setAttribute('aria-pressed', 'true');
  document.getElementById('path-text').textContent = 'Choose a source node from the graph or node list.';
  document.getElementById('path-banner').classList.add('visible');
  computeVisibility(); markDirty();
}

function handlePathClick(d) {
  if (pathSource && !pathTarget) {
    if (d.id === pathSource) return;
    pathTarget = d.id;
    runPathBFS();
  } else if (pathTarget && !pathSource) {
    if (d.id === pathTarget) return;
    pathSource = d.id;
    runPathBFS();
  } else {
    pathSource = d.id; pathTarget = null; pathResult = null;
    document.getElementById('path-text').textContent =
      'Source: ' + (d.label || d.id) + ' \u2014 click a target node...';
    computeVisibility(); markDirty();
  }
}

function runPathBFS() {
  pathResult = bfsShortestPath(pathSource, pathTarget);
  if (pathResult) {
    const srcLabel = nodeById.get(pathSource)?.label || pathSource;
    const tgtLabel = nodeById.get(pathTarget)?.label || pathTarget;
    document.getElementById('path-text').textContent =
      srcLabel + ' \u2192 ' + tgtLabel + ' (' + pathResult.hops.length +
      ' hop' + (pathResult.hops.length === 1 ? '' : 's') + ')';
    inspectPath(pathResult);
  } else {
    document.getElementById('path-text').textContent = 'No path found \u2014 click a new source...';
    pathSource = null; pathTarget = null; pathResult = null;
  }
  computeVisibility(); markDirty();
}

function exitPathMode() {
  if (!pathMode) return;
  pathMode = false; pathSource = null; pathTarget = null; pathResult = null;
  document.getElementById('btn-path').classList.remove('active');
  document.getElementById('btn-path').setAttribute('aria-pressed', 'false');
  document.getElementById('path-banner').classList.remove('visible');
  computeVisibility(); markDirty();
}

function enterPathModeFrom(nodeId) {
  exitFocusMode();
  pathMode = true; pathSource = nodeId; pathTarget = null; pathResult = null;
  document.getElementById('btn-path').classList.add('active');
  document.getElementById('btn-path').setAttribute('aria-pressed', 'true');
  document.getElementById('path-banner').classList.add('visible');
  document.getElementById('path-text').textContent =
    'Source: ' + (nodeById.get(nodeId)?.label || nodeId) + ' \u2014 click a target node...';
  computeVisibility(); markDirty();
}

function enterPathModeTo(nodeId) {
  exitFocusMode();
  pathMode = true; pathSource = null; pathTarget = nodeId; pathResult = null;
  document.getElementById('btn-path').classList.add('active');
  document.getElementById('btn-path').setAttribute('aria-pressed', 'true');
  document.getElementById('path-banner').classList.add('visible');
  document.getElementById('path-text').textContent =
    'Target: ' + (nodeById.get(nodeId)?.label || nodeId) + ' \u2014 click a source node...';
  computeVisibility(); markDirty();
}

// ── Focus mode ──────────────────────────────────────────────────────────────
function enterFocusMode(nodeId) {
  exitPathMode();
  focusNodeId = nodeId;
  document.getElementById('focus-text').textContent = 'Focused: ' + (nodeById.get(nodeId)?.label || nodeId);
  document.getElementById('focus-banner').classList.add('visible');
  computeVisibility(); markDirty();
}

function exitFocusMode() {
  if (!focusNodeId) return;
  focusNodeId = null;
  document.getElementById('focus-banner').classList.remove('visible');
  computeVisibility(); markDirty();
}

// ── Inspector ───────────────────────────────────────────────────────────────
function inspectNode(d) {
  const panel = document.getElementById('inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  panel.classList.add('open');
  document.getElementById('results-panel').classList.remove('open');
  document.getElementById('detail-empty').hidden = true;
  title.textContent = d.label || d.id;
  body.textContent = '';

  const m = kindMeta.get(d.kind) || {};
  const badge = el('span', {className: 'kind-badge', textContent: m.label || d.kind});
  badge.style.color = m.color || '#8c99a8';
  badge.style.borderColor = m.color || '#8c99a8';
  body.appendChild(badge);

  // Risk indicator dots
  const riskDiv = el('div', {className: 'risk-indicator'});
  const isInjectable = d.properties?.injectable;
  const hasTier0 = d.properties?.tier === 0;
  const isOwned = d.properties?.owned;
  const vulnLinks = (adjOut.get(d.id) || []).filter(e => e.link.kind === 'rs_AffectedBy');
  const hasKevVuln = vulnLinks.some(({target}) => nodeById.get(target)?.properties?.in_kev);

  const dots = [
    {active: isOwned || hasKevVuln || hasTier0, level: 'critical', title: 'Critical risk'},
    {active: isInjectable || d.properties?.tier === 1, level: 'high', title: 'High risk'},
    {active: vulnLinks.length > 0, level: 'medium', title: 'Medium risk'},
    {active: true, level: 'low', title: 'Baseline'},
  ];
  dots.forEach(({active, level, title: t}) => {
    const dot = el('span', {className: 'risk-dot' + (active ? ' active-' + level : ''), title: t});
    riskDiv.appendChild(dot);
  });
  body.appendChild(riskDiv);

  // Action buttons
  const actions = el('div', {className: 'inspector-actions'});
  actions.appendChild(el('button', {className: 'inspector-btn', textContent: 'Focus Neighbors',
    onclick: () => enterFocusMode(d.id)}));
  actions.appendChild(el('button', {className: 'inspector-btn', textContent: 'Path From',
    onclick: () => enterPathModeFrom(d.id)}));
  actions.appendChild(el('button', {className: 'inspector-btn', textContent: 'Path To',
    onclick: () => enterPathModeTo(d.id)}));
  actions.appendChild(el('button', {className: 'inspector-btn', textContent: 'Center',
    onclick: () => centerOnNode(d)}));
  body.appendChild(actions);

  const props = d.properties || {};
  const skip = new Set(['_icon', '_color']);

  // Split properties into important vs. secondary
  const importantKeys = new Set(['bundle_id', 'name', 'injectable', 'hardened_runtime',
    'library_validation', 'tier', 'owned', 'risk_score', 'cve_id', 'cvss_score',
    'epss_score', 'in_kev', 'sandboxed', 'electron', 'signed_by', 'attack_categories']);
  const entries = Object.entries(props).filter(([k]) => !skip.has(k));
  const importantEntries = entries.filter(([k]) => importantKeys.has(k));
  const secondaryEntries = entries.filter(([k]) => !importantKeys.has(k));

  if (importantEntries.length) {
    const sec = sectionHeader('Key Properties');
    importantEntries.forEach(entry => sec.appendChild(importantPropertyRow(entry)));
    body.appendChild(sec);
  }

  if (secondaryEntries.length) {
    const secH = sectionHeader('All Properties');
    const countSpan = el('span', {className: 'section-count', textContent: String(secondaryEntries.length)});
    secH.querySelector('h4').appendChild(countSpan);
    secondaryEntries.forEach(([k, v]) => secH.appendChild(propRow(k, v)));
    body.appendChild(secH);
  }

  // Vulnerability section: show CVE details for Application nodes
  if (vulnLinks.length) {
    const sec = sectionHeader('Vulnerabilities');
    const countSpan = el('span', {className: 'section-count', textContent: String(vulnLinks.length)});
    sec.querySelector('h4').appendChild(countSpan);
    vulnLinks.forEach(link => appendVulnerabilityRow(sec, link.target));
    body.appendChild(sec);
  }

  const outgoing = adjOut.get(d.id) || [];
  const incoming = adjIn.get(d.id) || [];

  if (outgoing.length) {
    const sec = sectionHeader('Outgoing Edges');
    const countSpan = el('span', {className: 'section-count', textContent: String(outgoing.length)});
    sec.querySelector('h4').appendChild(countSpan);
    outgoing.slice(0, 25).forEach(({target, link}) => {
      const tgt = nodeById.get(target);
      const label = edgeKinds.get(link.kind)?.label || link.kind;
      const row = propRow(label, tgt?.label || '?');
      if (link.properties?._traversable) row.classList.add('info-row');
      sec.appendChild(row);
    });
    if (outgoing.length > 25) sec.appendChild(propRow('\u2026', '+' + (outgoing.length - 25) + ' more'));
    body.appendChild(sec);
  }

  if (incoming.length) {
    const sec = sectionHeader('Incoming Edges');
    const countSpan = el('span', {className: 'section-count', textContent: String(incoming.length)});
    sec.querySelector('h4').appendChild(countSpan);
    incoming.slice(0, 25).forEach(({source, link}) => {
      const src = nodeById.get(source);
      const label = edgeKinds.get(link.kind)?.label || link.kind;
      const row = propRow(label, src?.label || '?');
      if (link.properties?._traversable) row.classList.add('info-row');
      sec.appendChild(row);
    });
    if (incoming.length > 25) sec.appendChild(propRow('\u2026', '+' + (incoming.length - 25) + ' more'));
    body.appendChild(sec);
  }
}

function importantPropertyRow([key, value]) {
  const row = propRow(key, value);
  const rowClasses = {
    'injectable:true': 'critical-row',
    'tier:0': 'critical-row',
    'hardened_runtime:false': 'warning-row',
    'owned:true': 'owned-row',
  };
  const rowClass = rowClasses[key + ':' + String(value)];
  if (rowClass) row.classList.add(rowClass);
  return row;
}

function vulnerabilityRowClass(properties) {
  if (properties.in_kev) return 'critical-row';
  return properties.epss_score > 0.5 ? 'warning-row' : 'info-row';
}

function appendVulnerabilityRow(section, targetId) {
  const vulnerability = nodeById.get(targetId);
  if (!vulnerability) return;
  const properties = vulnerability.properties || {};
  const cvss = properties.cvss_score != null ? String(properties.cvss_score) : '?';
  const epss = properties.epss_score != null ? Number(properties.epss_score).toFixed(2) : '\u2014';
  const kev = properties.in_kev ? ' KEV' : '';
  const label = (properties.cve_id || '?') + ' (CVSS ' + cvss + ', EPSS ' + epss + ')' + kev;
  const row = propRow(label, properties.title || '');
  row.classList.add(vulnerabilityRowClass(properties));
  section.appendChild(row);
}

function inspectPath(result) {
  const panel = document.getElementById('inspector');
  const title = document.getElementById('inspector-title');
  const body = document.getElementById('inspector-body');
  panel.classList.add('open');
  document.getElementById('results-panel').classList.remove('open');
  document.getElementById('detail-empty').hidden = true;
  title.textContent = 'Attack Path';
  body.textContent = '';

  // Path summary badge
  const summaryBadge = el('span', {className: 'kind-badge',
    textContent: result.hops.length + ' hop' + (result.hops.length > 1 ? 's' : '')});
  summaryBadge.classList.add('critical-badge');
  body.appendChild(summaryBadge);

  const sec = sectionHeader('Attack Chain');
  result.hops.forEach((hop, i) => {
    const fromNode = nodeById.get(hop.from);
    const toNode = nodeById.get(hop.to);
    const edgeLabel = edgeKinds.get(hop.edge.kind)?.label || hop.edge.kind;
    const row = propRow(
      (i + 1) + '. ' + (fromNode?.label || hop.from),
      edgeLabel + ' \u2192 ' + (toNode?.label || hop.to)
    );
    row.classList.add('critical-row');
    row.setAttribute('tabindex', '0');
    const activate = () => {
      const n = fromNode || toNode;
      if (n) { centerOnNode(n); selectedNode = n; inspectNode(n); markDirty(); }
    };
    row.addEventListener('click', activate);
    row.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); activate(); }
    });
    sec.appendChild(row);
  });
  body.appendChild(sec);
}

function closeInspector() {
  document.getElementById('inspector').classList.remove('open');
  document.getElementById('detail-empty').hidden = document.getElementById('results-panel').classList.contains('open');
}

// ── Context menu ────────────────────────────────────────────────────────────
function showContextMenu(event, d) {
  event.preventDefault(); event.stopPropagation();
  const menu = document.getElementById('context-menu');
  menu.textContent = '';

  function ctxItem(icon, text, handler) {
    const item = el('button', {type: 'button', role: 'menuitem', className: 'ctx-item', onclick: handler});
    item.appendChild(el('span', {className: 'ctx-icon', textContent: icon}));
    item.appendChild(el('span', {textContent: text}));
    return item;
  }
  menu.appendChild(ctxItem('\u2192', 'Find paths FROM this node',
    () => { hideContextMenu(); enterPathModeFrom(d.id); }));
  menu.appendChild(ctxItem('\u2190', 'Find paths TO this node',
    () => { hideContextMenu(); enterPathModeTo(d.id); }));
  menu.appendChild(el('div', {className: 'ctx-separator'}));
  menu.appendChild(ctxItem('\u25ce', 'Show neighbors only',
    () => { hideContextMenu(); enterFocusMode(d.id); }));
  menu.appendChild(ctxItem('\u2316', 'Center on this node',
    () => { hideContextMenu(); centerOnNode(d); }));
  menu.appendChild(el('div', {className: 'ctx-separator'}));

  const ownedLabel = d.properties?.owned ? 'Unmark as owned' : 'Mark as owned';
  const ownedIcon = d.properties?.owned ? '\u2610' : '\u2611';
  menu.appendChild(ctxItem(ownedIcon, ownedLabel,
    () => { hideContextMenu(); toggleOwned(d); }));

  const tierHeader = el('div', {className: 'ctx-item'});
  tierHeader.appendChild(el('span', {className: 'ctx-icon', textContent: '\u25b3'}));
  tierHeader.appendChild(el('span', {textContent: 'Set tier', style: 'color:#8b949e'}));
  tierHeader.style.cursor = 'default';
  menu.appendChild(tierHeader);
  ['T0', 'T1', 'T2', 'Clear'].forEach(t => {
    menu.appendChild(el('button', {type: 'button', role: 'menuitem', className: 'ctx-sub', textContent: t,
      onclick: () => { hideContextMenu(); setTier(d, t === 'Clear' ? null : parseInt(t[1])); }}));
  });

  const rect = container.getBoundingClientRect();
  menu.style.left = (event.clientX - rect.left) + 'px';
  menu.style.top = (event.clientY - rect.top) + 'px';
  menu.style.display = 'block';
}

function hideContextMenu() { document.getElementById('context-menu').style.display = 'none'; }
document.addEventListener('click', hideContextMenu);

function centerOnNode(d) {
  transform = {
    x: W / 2 - d.x * 1.5,
    y: H / 2 - d.y * 1.5,
    k: 1.5
  };
  markDirty();
}

function toggleOwned(d) {
  if (!d.properties) d.properties = {};
  d.properties.owned = !d.properties.owned;
  markDirty();
}

function setTier(d, tier) {
  if (!d.properties) d.properties = {};
  d.properties.tier = tier;
  markDirty();
}
