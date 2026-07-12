/* global module, nodeRadius, nodes, visibleNodeIds */
/* exported spatialIndex */

// ── Spatial grid for bounded hit-testing ────────────────────────────────────
class SpatialGrid {
  constructor(nodes, options = {}) {
    this.cellSize = 64;
    this.cells = new Map();
    this.isVisible = options.isVisible || (node => visibleNodeIds.has(node.id));
    this.radiusFor = options.radiusFor || nodeRadius;
    nodes.forEach(node => {
      const key = this.key(node.x, node.y);
      if (!this.cells.has(key)) this.cells.set(key, []);
      this.cells.get(key).push(node);
    });
  }

  key(x, y) {
    return Math.floor(x / this.cellSize) + ':' + Math.floor(y / this.cellSize);
  }

  candidatesNear(px, py, maxDist) {
    const radius = Math.ceil((maxDist + 24) / this.cellSize);
    const cx = Math.floor(px / this.cellSize);
    const cy = Math.floor(py / this.cellSize);
    const candidates = [];
    for (let x = cx - radius; x <= cx + radius; x++) {
      for (let y = cy - radius; y <= cy + radius; y++) {
        candidates.push(...(this.cells.get(x + ':' + y) || []));
      }
    }
    return candidates;
  }

  distanceFromNode(node, px, py, maxDist, bestDist) {
    if (!this.isVisible(node)) return null;
    const dx = node.x - px;
    const dy = node.y - py;
    const radius = this.radiusFor(node);
    const squaredDistance = dx * dx + dy * dy;
    const withinNode = squaredDistance < (radius + maxDist) ** 2;
    const couldBeCloser = squaredDistance < bestDist + radius * radius;
    if (!withinNode || !couldBeCloser) return null;
    return Math.sqrt(squaredDistance) - radius;
  }

  findNearest(px, py, maxDist) {
    let best = null;
    let bestDist = maxDist * maxDist;
    for (const node of this.candidatesNear(px, py, maxDist)) {
      const distance = this.distanceFromNode(node, px, py, maxDist, bestDist);
      if (distance === null || distance >= Math.sqrt(bestDist)) continue;
      bestDist = distance * distance;
      best = node;
    }
    return best;
  }
}

if (typeof module !== 'undefined') module.exports = {SpatialGrid};

let spatialIndex = typeof document === 'undefined' ? null : new SpatialGrid(nodes);
