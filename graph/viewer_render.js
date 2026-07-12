/* global H, W, adjIn, adjOut, container, ctx, degreeMap, dpr, edgeKinds, el */
/* global focusNodeId, hoverNode, kindMeta, linkKey, links, nodeById, nodeRadius */
/* global nodes, pathMode, pathResult, pathSource, pathTarget, pinnedNode */
/* global selectedNode, showLabels, transform, visibleLinkSet, visibleNodeIds */
/* global dirty:writable, frameRequested:writable, markDirty */
/* exported drawFrame, hideTooltip, showTooltip */
/* exported frameRequested */

// ── Node shapes ─────────────────────────────────────────────────────────────
const SHAPE_MAP = new Map(Object.entries({
  'rs_Vulnerability': 'diamond',
  'rs_AttackTechnique': 'diamond',
  'rs_ThreatGroup': 'diamond',
  'rs_CWE': 'diamond',
  'rs_TCCPermission': 'hexagon',
  'rs_Entitlement': 'hexagon',
  'rs_AuthRight': 'hexagon',
  'rs_SandboxProfile': 'hexagon',
  'rs_User': 'triangle',
  'rs_LocalGroup': 'triangle',
  'rs_ADUser': 'triangle',
  'rs_ADGroup': 'triangle',
  'rs_Computer': 'square',
  'rs_CriticalFile': 'square',
  'rs_Firewall': 'square',
  'rs_XPCService': 'roundrect',
  'rs_LaunchItem': 'roundrect',
  'rs_RemoteAccess': 'roundrect',
  'rs_LoginSession': 'roundrect',
  'rs_SystemExt': 'roundrect',
  'rs_Recommendation': 'roundrect',
}));

function drawDiamond(context, x, y, radius) {
  const size = radius * 1.3;
  context.moveTo(x, y - size);
  context.lineTo(x + size, y);
  context.lineTo(x, y + size);
  context.lineTo(x - size, y);
  context.closePath();
}

function drawHexagon(context, x, y, radius) {
  const size = radius * 1.1;
  for (let index = 0; index < 6; index++) {
    const angle = Math.PI / 6 + (Math.PI / 3) * index;
    const px = x + size * Math.cos(angle);
    const py = y + size * Math.sin(angle);
    if (index === 0) context.moveTo(px, py);
    else context.lineTo(px, py);
  }
  context.closePath();
}

function drawRoundedBox(context, x, y, width, height, cornerRadius) {
  context.moveTo(x - width + cornerRadius, y - height);
  context.lineTo(x + width - cornerRadius, y - height);
  context.arcTo(x + width, y - height, x + width, y - height + cornerRadius, cornerRadius);
  context.lineTo(x + width, y + height - cornerRadius);
  context.arcTo(x + width, y + height, x + width - cornerRadius, y + height, cornerRadius);
  context.lineTo(x - width + cornerRadius, y + height);
  context.arcTo(x - width, y + height, x - width, y + height - cornerRadius, cornerRadius);
  context.lineTo(x - width, y - height + cornerRadius);
  context.arcTo(x - width, y - height, x - width + cornerRadius, y - height, cornerRadius);
  context.closePath();
}

function drawSquare(context, x, y, radius) {
  const size = radius * 0.9;
  drawRoundedBox(context, x, y, size, size, size * 0.2);
}

function drawTriangle(context, x, y, radius) {
  const size = radius * 1.2;
  context.moveTo(x, y - size);
  context.lineTo(x + size * 0.87, y + size * 0.5);
  context.lineTo(x - size * 0.87, y + size * 0.5);
  context.closePath();
}

function drawRoundRect(context, x, y, radius) {
  drawRoundedBox(context, x, y, radius * 1.5, radius * 0.9, radius * 0.35);
}

function drawCircle(context, x, y, radius) {
  context.arc(x, y, radius, 0, Math.PI * 2);
}

const NODE_SHAPE_DRAWERS = new Map(Object.entries({
  diamond: drawDiamond,
  hexagon: drawHexagon,
  square: drawSquare,
  triangle: drawTriangle,
  roundrect: drawRoundRect,
}));
const TIER_CLASSES = new Map([[0, 'critical'], [1, 'high'], [2, 'medium']]);

function drawNodeShape(context, x, y, radius, shape) {
  const drawer = NODE_SHAPE_DRAWERS.get(shape) || drawCircle;
  drawer(context, x, y, radius);
}

function getNodeShape(kind) {
  return SHAPE_MAP.get(kind) || 'circle';
}

// ── Drawing ─────────────────────────────────────────────────────────────────
const ARROW_SIZE = 6;

function viewportBounds() {
  return {
    x0: -transform.x / transform.k - 100,
    y0: -transform.y / transform.k - 100,
    x1: (W - transform.x) / transform.k + 100,
    y1: (H - transform.y) / transform.k + 100,
  };
}

function collectNeighborHighlights(entries, nodeIds, edgeSet) {
  for (const entry of entries) {
    nodeIds.add(entry.target || entry.source);
    edgeSet.add(entry.link);
  }
}

function neighborHighlightState() {
  const candidate = pinnedNode || hoverNode;
  const node = pathMode || focusNodeId ? null : candidate;
  const nodeIds = new Set(node ? [node.id] : []);
  const edgeSet = new Set();
  if (!node) return {active: false, nodeIds, edgeSet};
  collectNeighborHighlights(adjOut.get(node.id) || [], nodeIds, edgeSet);
  collectNeighborHighlights(adjIn.get(node.id) || [], nodeIds, edgeSet);
  return {active: true, nodeIds, edgeSet};
}

function edgeInViewport(source, target, viewport) {
  const minX = Math.min(source.x, target.x);
  const maxX = Math.max(source.x, target.x);
  const minY = Math.min(source.y, target.y);
  const maxY = Math.max(source.y, target.y);
  return !(maxX < viewport.x0 || minX > viewport.x1 ||
    maxY < viewport.y0 || minY > viewport.y1);
}

function baseEdgeStyle(link, visible) {
  const traversable = link.properties?._traversable;
  return {
    alpha: visible ? (traversable ? 0.5 : 0.2) : 0.03,
    color: traversable ? '#58a6ff' : '#30363d',
    width: traversable ? 1.5 : 0.7,
    dashed: !traversable && visible,
  };
}

function edgeStyle(link, visible, highlight) {
  const traversable = link.properties?._traversable;
  const style = baseEdgeStyle(link, visible);
  if (pathMode && pathResult?.linkKeys.has(linkKey(link))) {
    return {...style, alpha: 1, color: '#f85149', width: 3};
  }
  if (!highlight.active) return style;
  if (!highlight.edgeSet.has(link)) return {...style, alpha: 0.03};
  return {
    ...style,
    alpha: 0.85,
    color: traversable ? '#79c0ff' : '#8b949e',
    width: traversable ? 2.5 : 1.5,
  };
}

function drawArrow(source, target, color) {
  if (transform.k <= 0.3) return;
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const distance = Math.sqrt(dx * dx + dy * dy);
  if (distance === 0) return;
  const targetRadius = nodeRadius(target);
  const x = target.x - (dx / distance) * (targetRadius + 2);
  const y = target.y - (dy / distance) * (targetRadius + 2);
  const angle = Math.atan2(dy, dx);
  const size = ARROW_SIZE / transform.k;
  ctx.beginPath();
  ctx.moveTo(x, y);
  ctx.lineTo(x - size * Math.cos(angle - 0.4), y - size * Math.sin(angle - 0.4));
  ctx.lineTo(x - size * Math.cos(angle + 0.4), y - size * Math.sin(angle + 0.4));
  ctx.closePath();
  ctx.fillStyle = color;
  ctx.fill();
}

function drawGraphEdge(link, index, viewport, highlight) {
  const visible = visibleLinkSet.has(index);
  if (!visible && !highlight.active) return;
  const source = nodeById.get(link.source);
  const target = nodeById.get(link.target);
  if (!source || !target || !edgeInViewport(source, target, viewport)) return;
  const style = edgeStyle(link, visible, highlight);
  ctx.beginPath();
  ctx.setLineDash(style.dashed && style.alpha > 0.05
    ? [4 / transform.k, 3 / transform.k] : []);
  ctx.moveTo(source.x, source.y);
  ctx.lineTo(target.x, target.y);
  ctx.strokeStyle = style.color;
  ctx.globalAlpha = style.alpha;
  ctx.lineWidth = style.width / transform.k;
  ctx.stroke();
  ctx.setLineDash([]);
  drawArrow(source, target, style.color);
}

function nodeStroke(node) {
  if (selectedNode?.id === node.id) {
    return {color: '#f0f6fc', width: 2.5 / transform.k};
  }
  if (!pathMode || !pathResult) return {color: '#21262d', width: 1.5 / transform.k};
  if (node.id === pathSource || node.id === pathTarget) {
    return {color: node.id === pathSource ? '#3fb950' : '#f85149', width: 3 / transform.k};
  }
  if (pathResult.nodeIds.has(node.id)) return {color: '#f85149', width: 2 / transform.k};
  return {color: '#21262d', width: 1.5 / transform.k};
}

function applyNodeShadow(node) {
  const shadowByLevel = {
    critical: ['#f85149', 10],
    high: ['#d29922', 8],
  };
  const shadow = node.properties?.owned
    ? ['#ffd700', 14]
    : shadowByLevel[node.properties?.risk_level];
  ctx.shadowColor = shadow?.[0] || 'transparent';
  ctx.shadowBlur = (shadow?.[1] || 0) / transform.k;
}

function drawRiskRing(node, radius, alpha) {
  const score = node.properties?.risk_score;
  if (score == null || score < 25 || transform.k <= 0.25) return;
  const color = score >= 75 ? '#f85149' : score >= 50 ? '#d29922' : '#58a6ff';
  ctx.beginPath();
  ctx.arc(node.x, node.y, radius + 4 / transform.k, -Math.PI / 2,
    -Math.PI / 2 + (score / 100) * Math.PI * 2);
  ctx.strokeStyle = color;
  ctx.globalAlpha = alpha * Math.min(0.8, score / 100);
  ctx.lineWidth = 2.5 / transform.k;
  ctx.stroke();
  ctx.globalAlpha = alpha;
}

function vulnerabilityState(node) {
  const vulnerabilities = (adjOut.get(node.id) || [])
    .filter(edge => edge.link.kind === 'rs_AffectedBy')
    .map(edge => nodeById.get(edge.target))
    .filter(Boolean);
  return {
    present: vulnerabilities.length > 0,
    kev: vulnerabilities.some(item => item.properties?.in_kev),
    highEpss: vulnerabilities.some(item => item.properties?.epss_score > 0.5),
  };
}

function drawVulnerabilityRing(node, radius) {
  const state = vulnerabilityState(node);
  if (!state.present || (!state.kev && !state.highEpss) || transform.k <= 0.2) return;
  ctx.beginPath();
  ctx.arc(node.x, node.y, radius + 3 / transform.k, 0, Math.PI * 2);
  ctx.strokeStyle = state.kev ? '#f85149' : '#d29922';
  ctx.lineWidth = 2 / transform.k;
  ctx.setLineDash([3 / transform.k, 2 / transform.k]);
  ctx.stroke();
  ctx.setLineDash([]);
}

function drawTierBadge(node, radius) {
  if (node.properties?.tier == null || transform.k <= 0.3) return;
  const colors = {'0': '#f85149', '1': '#d29922', '2': '#58a6ff'};
  const x = node.x + radius * 0.65;
  const y = node.y - radius * 0.65;
  const badgeRadius = Math.max(5, 6 / transform.k);
  ctx.beginPath();
  ctx.arc(x, y, badgeRadius, 0, Math.PI * 2);
  ctx.fillStyle = colors[String(node.properties.tier)] || '#8b949e';
  ctx.fill();
  ctx.fillStyle = '#fff';
  ctx.font = `bold ${Math.max(6, 6 / transform.k)}px -apple-system, sans-serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(String(node.properties.tier), x, y + 0.5);
}

function shouldLabelNode(node, showAll, showHighDegree) {
  const highDegree = showHighDegree && (degreeMap.get(node.id) || 0) > 5;
  const hovered = hoverNode?.id === node.id;
  const selected = selectedNode?.id === node.id;
  const pathEndpoint = pathMode && pathResult &&
    [pathSource, pathTarget].includes(node.id);
  return [showAll, highDegree, hovered, selected, pathEndpoint].some(Boolean);
}

function drawNodeLabel(node, radius) {
  if (!node.label) return;
  const fontSize = Math.max(9, Math.min(12, 10 / transform.k));
  const label = node.label.length > 24 ? node.label.slice(0, 23) + '…' : node.label;
  ctx.font = `500 ${fontSize}px -apple-system, sans-serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  const width = ctx.measureText(label).width;
  const y = node.y + radius + 4;
  ctx.fillStyle = 'rgba(13,17,23,.75)';
  ctx.beginPath();
  ctx.roundRect(node.x - width / 2 - 3, y - 1, width + 6, fontSize + 3, 3);
  ctx.fill();
  ctx.fillStyle = '#c9d1d9';
  ctx.fillText(label, node.x, y);
}

function nodeInViewport(node, viewport) {
  return node.x >= viewport.x0 && node.x <= viewport.x1 &&
    node.y >= viewport.y0 && node.y <= viewport.y1;
}

function nodeAlpha(node, visible, highlight) {
  if (!highlight.active) return visible ? 1 : 0.1;
  return highlight.nodeIds.has(node.id) ? 1 : 0.08;
}

function drawGraphNode(node, viewport, highlight, labels) {
  if (!nodeInViewport(node, viewport)) return;
  const visible = visibleNodeIds.has(node.id);
  if (!visible && !highlight.active) return;
  const radius = nodeRadius(node);
  const alpha = nodeAlpha(node, visible, highlight);
  const stroke = nodeStroke(node);
  ctx.globalAlpha = alpha;
  applyNodeShadow(node);
  ctx.beginPath();
  drawNodeShape(ctx, node.x, node.y, radius, getNodeShape(node.kind));
  ctx.fillStyle = node.properties?._color || kindMeta.get(node.kind)?.color || '#888';
  ctx.fill();
  ctx.strokeStyle = stroke.color;
  ctx.lineWidth = stroke.width;
  ctx.stroke();
  ctx.shadowColor = 'transparent';
  ctx.shadowBlur = 0;
  drawRiskRing(node, radius, alpha);
  drawVulnerabilityRing(node, radius);
  drawTierBadge(node, radius);
  if (shouldLabelNode(node, labels.showAll, labels.showHighDegree)) drawNodeLabel(node, radius);
}

function drawEdgeLabel(source, target, text, color, fontSize) {
  const x = (source.x + target.x) / 2;
  const y = (source.y + target.y) / 2;
  const width = ctx.measureText(text).width;
  ctx.fillStyle = 'rgba(13,17,23,.8)';
  ctx.beginPath();
  ctx.roundRect(x - width / 2 - 4, y - fontSize / 2 - 2, width + 8, fontSize + 4, 3);
  ctx.fill();
  ctx.fillStyle = color;
  ctx.fillText(text, x, y);
}

function labelEdge(link, color, fontSize) {
  const source = nodeById.get(link.source);
  const target = nodeById.get(link.target);
  if (!source || !target) return;
  drawEdgeLabel(source, target, edgeKinds.get(link.kind)?.label || link.kind, color, fontSize);
}

function drawEdgeLabels(highlight) {
  if (transform.k <= 0.5) return;
  const fontSize = Math.max(8, 9 / transform.k);
  ctx.globalAlpha = 0.85;
  ctx.font = `500 ${fontSize}px -apple-system, sans-serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  if (highlight.active) {
    for (const link of highlight.edgeSet) labelEdge(link, '#c9d1d9', fontSize);
  }
  if (pathMode && pathResult) {
    for (const link of links) {
      if (pathResult.linkKeys.has(linkKey(link))) labelEdge(link, '#f85149', fontSize);
    }
  }
}

function prepareCanvas() {
  ctx.save();
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = getComputedStyle(document.documentElement)
    .getPropertyValue('--canvas').trim() || '#0b1016';
  ctx.fillRect(0, 0, W, H);
  ctx.translate(transform.x, transform.y);
  ctx.scale(transform.k, transform.k);
}

function drawVisibleEdges(viewport, highlight) {
  for (const [index, link] of links.entries()) {
    drawGraphEdge(link, index, viewport, highlight);
  }
}

function drawVisibleNodes(viewport, highlight, labels) {
  for (const node of nodes) drawGraphNode(node, viewport, highlight, labels);
}

const tooltip = document.getElementById('tooltip');
markDirty();

// ── Tooltip ─────────────────────────────────────────────────────────────────
function appendTooltipBadge(parent, className, text) {
  parent.appendChild(el('span', {className: 'tt-risk ' + className, textContent: text}));
}

function appendTooltipRisk(parent, node) {
  if (node.properties?.owned) appendTooltipBadge(parent, 'owned', 'OWNED');
  const tier = node.properties?.tier;
  const tierClass = TIER_CLASSES.get(tier);
  if (tierClass) appendTooltipBadge(parent, tierClass, 'TIER ' + tier);
  const level = node.properties?.risk_level;
  if (level) appendTooltipBadge(parent, ['critical', 'high', 'medium'].includes(level) ? level : 'low', level.toUpperCase());
}

function appendTooltipScore(parent, node) {
  const score = node.properties?.risk_score;
  if (score == null) return;
  const color = score >= 75 ? '#f85149' : score >= 50 ? '#d29922'
    : score >= 25 ? '#58a6ff' : '#3fb950';
  const badge = el('span', {className: 'tt-score', textContent: String(score)});
  badge.style.background = color + '25';
  badge.style.color = color;
  badge.style.border = '1px solid ' + color + '40';
  parent.appendChild(badge);
}

function appendDetail(details, condition, value) {
  if (condition) details.push(value);
}

function tooltipDetails(node) {
  const details = [];
  const degree = degreeMap.get(node.id) || 0;
  const vulnerabilities = (adjOut.get(node.id) || [])
    .filter(edge => edge.link.kind === 'rs_AffectedBy').length;
  const cveLabel = vulnerabilities + ' CVE' + (vulnerabilities === 1 ? '' : 's');
  appendDetail(details, degree > 0, degree + ' connections');
  appendDetail(details, vulnerabilities > 0, cveLabel);
  appendDetail(details, node.properties?.injectable, '[!] Injectable');
  appendDetail(details, node.properties?.hardened_runtime === false, '[!] No hardened runtime');
  appendDetail(details, node.properties?.sandboxed === false, '[!] Not sandboxed');
  appendDetail(details, Boolean(node.properties?.bundle_id), node.properties?.bundle_id);
  return details;
}

function positionTooltip(event) {
  const rect = container.getBoundingClientRect();
  let x = event.clientX - rect.left + 16;
  let y = event.clientY - rect.top - 8;
  if (x + 320 > rect.width) x = event.clientX - rect.left - 330;
  if (y + 100 > rect.height) y = rect.height - 110;
  tooltip.style.left = x + 'px';
  tooltip.style.top = y + 'px';
}

function showTooltip(event, node) {
  const meta = kindMeta.get(node.kind) || {};
  tooltip.hidden = false;
  tooltip.textContent = '';
  tooltip.appendChild(el('div', {className: 'tt-label', textContent: node.label || '?'}));
  const kind = el('div', {className: 'tt-kind'});
  const dot = el('span');
  dot.style.cssText = 'display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle;background:' + (meta.color || '#8b949e');
  kind.appendChild(dot);
  kind.appendChild(el('span', {textContent: meta.label || node.kind}));
  appendTooltipRisk(kind, node);
  appendTooltipScore(kind, node);
  tooltip.appendChild(kind);
  const details = tooltipDetails(node);
  if (details.length) tooltip.appendChild(el('div', {className: 'tt-detail', textContent: details.join(' · ')}));
  tooltip.classList.add('visible');
  positionTooltip(event);
}

function hideTooltip() {
  tooltip.classList.remove('visible');
  tooltip.hidden = true;
}

function drawFrame() {
  frameRequested = false;
  if (!dirty) return;
  dirty = false;
  prepareCanvas();
  const viewport = viewportBounds();
  const highlight = neighborHighlightState();
  const labels = {
    showAll: showLabels && transform.k >= 0.4,
    showHighDegree: showLabels && transform.k >= 0.2 && transform.k < 0.4,
  };
  drawVisibleEdges(viewport, highlight);
  ctx.globalAlpha = 1;
  drawVisibleNodes(viewport, highlight, labels);
  drawEdgeLabels(highlight);
  ctx.globalAlpha = 1;
  ctx.restore();
}
