/** Indexes rendered nodes for fast canvas hit testing. */

import type { NodeId } from "./types";

export interface PositionedNode {
  id: NodeId;
  x: number;
  y: number;
}

export interface SpatialGridOptions<T extends PositionedNode> {
  isVisible?: (node: T) => boolean;
  radiusFor?: (node: T) => number;
  positionFor?: (node: T) => { x: number; y: number };
  cellSize?: number;
}

/** Tracks position changes incrementally; visibility is evaluated at hit-test time. */
export class SpatialGrid<T extends PositionedNode> {
  private readonly cellSize: number;
  private maxRadius = 0;
  private readonly cells = new Map<string, Set<T>>();
  private readonly memberships = new Map<NodeId, { key: string; node: T }>();
  private readonly isVisible: (node: T) => boolean;
  private readonly radiusFor: (node: T) => number;
  private readonly positionFor: (node: T) => { x: number; y: number };

  constructor(nodes: readonly T[], options: SpatialGridOptions<T> = {}) {
    this.cellSize = options.cellSize ?? 64;
    this.isVisible = options.isVisible ?? (() => true);
    this.radiusFor = options.radiusFor ?? (() => 8);
    this.positionFor = options.positionFor ?? ((node) => node);
    for (const node of nodes) this.update(node);
  }

  update(node: T): void {
    this.maxRadius = Math.max(this.maxRadius, this.radiusFor(node));
    const position = this.positionFor(node);
    const key = this.key(position.x, position.y);
    const previous = this.memberships.get(node.id);
    if (previous?.key === key && previous.node === node) return;
    if (previous) {
      const cell = this.cells.get(previous.key);
      if (cell) {
        cell.delete(previous.node);
        if (cell.size === 0) this.cells.delete(previous.key);
      }
    }
    const cell = this.cells.get(key) ?? new Set<T>();
    cell.add(node);
    this.cells.set(key, cell);
    this.memberships.set(node.id, { key, node });
  }

  private key(x: number, y: number): string {
    return `${Math.floor(x / this.cellSize)}:${Math.floor(y / this.cellSize)}`;
  }

  private candidatesNear(px: number, py: number, maxDistance: number): T[] {
    const radius = Math.ceil((maxDistance + this.maxRadius) / this.cellSize);
    const cx = Math.floor(px / this.cellSize);
    const cy = Math.floor(py / this.cellSize);
    const candidates: T[] = [];
    for (let x = cx - radius; x <= cx + radius; x += 1) {
      for (let y = cy - radius; y <= cy + radius; y += 1) {
        candidates.push(...(this.cells.get(`${x}:${y}`) ?? []));
      }
    }
    return candidates;
  }

  findNearest(px: number, py: number, maxDistance: number): T | null {
    let best: T | null = null;
    let bestDistance = Number.POSITIVE_INFINITY;
    for (const node of this.candidatesNear(px, py, maxDistance)) {
      if (!this.isVisible(node)) continue;
      const position = this.positionFor(node);
      const centerDistance = Math.hypot(position.x - px, position.y - py);
      if (centerDistance > this.radiusFor(node) + maxDistance) continue;
      const distance = Math.max(0, centerDistance - this.radiusFor(node));
      if (
        distance < bestDistance ||
        (distance === bestDistance && best !== null && node.id < best.id)
      ) {
        best = node;
        bestDistance = distance;
      }
    }
    return best;
  }
}
