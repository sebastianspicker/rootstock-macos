/** Indexes rendered nodes for fast canvas hit testing. */

import type {NodeId} from "./types";

export interface PositionedNode {
  id: NodeId;
  x: number;
  y: number;
}

export interface SpatialGridOptions<T extends PositionedNode> {
  isVisible?: (node: T) => boolean;
  radiusFor?: (node: T) => number;
  positionFor?: (node: T) => {x: number; y: number};
  cellSize?: number;
}

/** Is rebuilt by callers whenever positions or visibility rules change, keeping hit tests aligned with the frame. */
export class SpatialGrid<T extends PositionedNode> {
  private readonly cellSize: number;
  private readonly cells = new Map<string, T[]>();
  private readonly isVisible: (node: T) => boolean;
  private readonly radiusFor: (node: T) => number;
  private readonly positionFor: (node: T) => {x: number; y: number};

  constructor(nodes: readonly T[], options: SpatialGridOptions<T> = {}) {
    this.cellSize = options.cellSize ?? 64;
    this.isVisible = options.isVisible ?? (() => true);
    this.radiusFor = options.radiusFor ?? (() => 8);
    this.positionFor = options.positionFor ?? ((node) => node);
    for (const node of nodes) {
      const position = this.positionFor(node);
      const key = this.key(position.x, position.y);
      const values = this.cells.get(key) ?? [];
      values.push(node);
      this.cells.set(key, values);
    }
  }

  private key(x: number, y: number): string {
    return `${Math.floor(x / this.cellSize)}:${Math.floor(y / this.cellSize)}`;
  }

  private candidatesNear(px: number, py: number, maxDistance: number): T[] {
    const radius = Math.ceil((maxDistance + 24) / this.cellSize);
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
      if (distance < bestDistance
          || (distance === bestDistance && best !== null && node.id < best.id)) {
        best = node;
        bestDistance = distance;
      }
    }
    return best;
  }
}
