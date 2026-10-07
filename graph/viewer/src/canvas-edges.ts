/** Draws relationships: observed ink, inferred pencil dashes, modeled-path emphasis, and labels. */
import {
  intersects,
  viewportBounds,
  textWidth,
  canvasFont,
  canvasLabelColor,
} from "./canvas-cache";
import type { Bounds } from "./canvas-cache";
import { linkKey, nodeRadius } from "./model";
import type { Controller } from "./runtime";
import type { GraphEdge, ParallelSlot } from "./types";
import type { CanvasHandlers } from "./canvas";

type Point = { x: number; y: number };

export interface EdgeStyle {
  color: string;
  dash: number[];
  width: number;
  alpha: number;
}

/** A drawn relationship: endpoints trimmed to the node outlines and a quadratic control point. */
export interface EdgeCurve {
  source: Point;
  control: Point;
  target: Point;
  loop: { center: Point; radius: number } | null;
}

type EdgeLabelJob = { text: string; curve: EdgeCurve; onPath: boolean };

const LABEL_LINK_LIMIT = 150;
const LABEL_MIN_ZOOM = 0.75;
const PARALLEL_SPACING = 18;

export function edgeIsInferred(edge: GraphEdge): boolean {
  return edge.properties?.inferred === true || edge.properties?._inferred === true;
}

/** Matches path traversal: only an explicit `_traversable: false` opts a relationship out. */
export function edgeIsTraversable(edge: GraphEdge): boolean {
  return edge.properties?._traversable !== false;
}

/** Inferred material is pencil blue and dashed; observed relationships are solid ink. */
export function edgeStyle(edge: GraphEdge, onPath: boolean, k: number): EdgeStyle {
  const inferred = edgeIsInferred(edge);
  const dash = inferred ? [7 / k, 5 / k] : [];
  if (onPath)
    return { color: canvasLabelColor("--path", "#33528a"), dash, width: 2.6 / k, alpha: 1 };
  if (inferred)
    return {
      color: canvasLabelColor("--annotation", "#33528a"),
      dash,
      width: 1.3 / k,
      alpha: 0.68,
    };
  if (edgeIsTraversable(edge))
    return { color: canvasLabelColor("--edge", "#4a453b"), dash, width: 1.3 / k, alpha: 0.68 };
  return { color: canvasLabelColor("--edge-faint", "#5c564b"), dash, width: 1.3 / k, alpha: 0.5 };
}

export function drawEdges(
  controller: Controller,
  worldPosition: CanvasHandlers["worldPosition"],
): void {
  const { state } = controller;
  const { context } = controller.dom;
  const labels: EdgeLabelJob[] = [];
  const denseLabels = state.render.visibleLinkIndexes.size <= LABEL_LINK_LIMIT;
  state.graph.links.forEach((edge, index) => {
    if (!state.render.visibleLinkIndexes.has(index)) return;
    const job = drawEdge(controller, edge, index, worldPosition);
    if (job && (denseLabels || job.onPath || touchesFocus(controller, edge))) labels.push(job);
  });
  if (state.selection.showLabels && state.viewport.transform.k >= LABEL_MIN_ZOOM)
    for (const job of labels) drawEdgeLabel(controller, job);
  context.globalAlpha = 1;
  context.setLineDash([]);
}

function touchesFocus(controller: Controller, edge: GraphEdge): boolean {
  const { selectedId, pinnedId, hoveredId } = controller.state.selection;
  return [selectedId, pinnedId, hoveredId].some(
    (id) => id !== null && (edge.source === id || edge.target === id),
  );
}

/** Returns a label job when the relationship has a kind worth labelling. */
function drawEdge(
  controller: Controller,
  edge: GraphEdge,
  index: number,
  worldPosition: CanvasHandlers["worldPosition"],
): EdgeLabelJob | null {
  const { graph, viewport, selection } = controller.state;
  const source = graph.nodeById.get(edge.source);
  const target = graph.nodeById.get(edge.target);
  if (!source || !target) return null;
  const k = viewport.transform.k;
  const onPath = selection.path.result?.linkKeys.has(linkKey(edge)) === true;
  const curve = edgeCurve(
    worldPosition(controller, source),
    worldPosition(controller, target),
    { source: nodeRadius(graph, source.id), target: nodeRadius(graph, target.id) },
    graph.parallel[index] ?? { index: 0, count: 1 },
    k,
  );
  if (!intersects(viewportBounds(controller), curveBounds(curve, 10))) return null;
  const style = edgeStyle(edge, onPath, k);
  style.alpha = Math.min(style.alpha, edgeDimAlpha(controller, edge, onPath));
  strokeCurve(controller.dom.context, curve, style);
  drawEdgeEnd(controller.dom.context, curve, style, edgeIsTraversable(edge), k);
  return edge.kind ? { text: edge.kind.replace(/^rs_/, ""), curve, onPath } : null;
}

/** Hover quiets unrelated relationships; a retained path quiets everything off the path. */
function edgeDimAlpha(controller: Controller, edge: GraphEdge, onPath: boolean): number {
  const { selection, workspace } = controller.state;
  let alpha = 1;
  if (
    selection.hoveredId &&
    edge.source !== selection.hoveredId &&
    edge.target !== selection.hoveredId
  )
    alpha = 0.3;
  if (workspace === "graph" && selection.path.result && !onPath) alpha = Math.min(alpha, 0.15);
  return alpha;
}

export function edgeCurve(
  source: Point,
  target: Point,
  radii: { source: number; target: number },
  slot: ParallelSlot,
  k: number,
): EdgeCurve {
  if (source.x === target.x && source.y === target.y) {
    const radius = 10 + slot.index * 6;
    const center = { x: source.x, y: source.y - radii.source - radius + 4 };
    return { source, control: center, target, loop: { center, radius } };
  }
  const offset = (slot.index - (slot.count - 1) / 2) * (PARALLEL_SPACING / k);
  // Reverse links share a perpendicular so their offsets land on opposite sides.
  const [first, second] =
    source.x < target.x || (source.x === target.x && source.y < target.y)
      ? [source, target]
      : [target, source];
  const length = Math.max(1, Math.hypot(second.x - first.x, second.y - first.y));
  const normal = { x: -(second.y - first.y) / length, y: (second.x - first.x) / length };
  const control = {
    x: (source.x + target.x) / 2 + normal.x * offset,
    y: (source.y + target.y) / 2 + normal.y * offset,
  };
  return {
    source: towards(source, control, radii.source),
    control,
    target: towards(target, control, radii.target + 5),
    loop: null,
  };
}

function towards(from: Point, to: Point, distance: number): Point {
  const length = Math.max(1, Math.hypot(to.x - from.x, to.y - from.y));
  return {
    x: from.x + ((to.x - from.x) / length) * distance,
    y: from.y + ((to.y - from.y) / length) * distance,
  };
}

/** Kept for callers that only need a straight trimmed segment. */
export function edgeSegment(
  source: Point,
  target: Point,
  sourceRadius: number,
  targetRadius: number,
): { source: Point; target: Point } {
  return {
    source: towards(source, target, sourceRadius),
    target: towards(target, source, targetRadius + 5),
  };
}

function curveBounds(curve: EdgeCurve, margin: number): Bounds {
  if (curve.loop) {
    const { center, radius } = curve.loop;
    return {
      left: center.x - radius - margin,
      right: center.x + radius + margin,
      top: center.y - radius - margin,
      bottom: center.y + radius + margin,
    };
  }
  const xs = [curve.source.x, curve.control.x, curve.target.x];
  const ys = [curve.source.y, curve.control.y, curve.target.y];
  return {
    left: Math.min(...xs) - margin,
    right: Math.max(...xs) + margin,
    top: Math.min(...ys) - margin,
    bottom: Math.max(...ys) + margin,
  };
}

function strokeCurve(context: CanvasRenderingContext2D, curve: EdgeCurve, style: EdgeStyle): void {
  context.beginPath();
  if (curve.loop)
    context.arc(curve.loop.center.x, curve.loop.center.y, curve.loop.radius, 0, Math.PI * 2);
  else {
    context.moveTo(curve.source.x, curve.source.y);
    context.quadraticCurveTo(curve.control.x, curve.control.y, curve.target.x, curve.target.y);
  }
  context.strokeStyle = style.color;
  context.globalAlpha = style.alpha;
  context.lineWidth = style.width;
  context.setLineDash(style.dash);
  context.stroke();
  context.setLineDash([]);
}

/** Traversable relationships end in a filled arrowhead; others in a quieter open circle. */
function drawEdgeEnd(
  context: CanvasRenderingContext2D,
  curve: EdgeCurve,
  style: EdgeStyle,
  traversable: boolean,
  k: number,
): void {
  if (curve.loop) return;
  if (traversable) {
    drawArrowhead(context, curve.control, curve.target, style.color, 8 / k);
    return;
  }
  const back = towards(curve.target, curve.control, 3 / k);
  context.beginPath();
  context.arc(back.x, back.y, 3 / k, 0, Math.PI * 2);
  context.fillStyle = canvasLabelColor("--ink-deep", "#f8f5ef");
  context.fill();
  context.lineWidth = 1.2 / k;
  context.strokeStyle = style.color;
  context.stroke();
}

export function drawArrowhead(
  context: CanvasRenderingContext2D,
  source: Point,
  target: Point,
  color: string,
  size = 8,
): void {
  const angle = Math.atan2(target.y - source.y, target.x - source.x);
  context.beginPath();
  context.moveTo(target.x, target.y);
  for (const spread of [-Math.PI / 6, Math.PI / 6])
    context.lineTo(
      target.x - Math.cos(angle + spread) * size,
      target.y - Math.sin(angle + spread) * size,
    );
  context.closePath();
  context.fillStyle = color;
  context.fill();
}

/** Midpoint and tangent of the quadratic at t = 0.5, or the top of a self-loop. */
function labelAnchor(curve: EdgeCurve): { point: Point; angle: number } {
  if (curve.loop)
    return {
      point: { x: curve.loop.center.x, y: curve.loop.center.y - curve.loop.radius },
      angle: 0,
    };
  const point = {
    x: 0.25 * curve.source.x + 0.5 * curve.control.x + 0.25 * curve.target.x,
    y: 0.25 * curve.source.y + 0.5 * curve.control.y + 0.25 * curve.target.y,
  };
  let angle = Math.atan2(curve.target.y - curve.source.y, curve.target.x - curve.source.x);
  // Keep text upright: flip anything that would read upside down.
  if (angle > Math.PI / 2) angle -= Math.PI;
  else if (angle < -Math.PI / 2) angle += Math.PI;
  return { point, angle };
}

/** Labels sit on a ground-colored pill, rotated along the relationship, at a constant screen size. */
export function drawEdgeLabel(controller: Controller, job: EdgeLabelJob): void {
  const { context } = controller.dom;
  const k = controller.state.viewport.transform.k;
  const width = textWidth(context, canvasFont("400", 11), job.text) / k;
  const height = 16 / k;
  const { point, angle } = labelAnchor(job.curve);
  const reach = width / 2 + 6 / k;
  const bounds = {
    left: point.x - reach,
    right: point.x + reach,
    top: point.y - reach,
    bottom: point.y + reach,
  };
  if (!intersects(viewportBounds(controller), bounds)) return;
  context.save();
  context.translate(point.x, point.y);
  context.rotate(angle);
  context.globalAlpha = 0.9;
  context.fillStyle = canvasLabelColor("--ink-deep", "#f8f5ef");
  context.beginPath();
  context.roundRect(-width / 2 - 5 / k, -height / 2, width + 10 / k, height, height / 2);
  context.fill();
  context.globalAlpha = job.onPath ? 1 : 0.95;
  context.fillStyle = job.onPath
    ? canvasLabelColor("--path", "#33528a")
    : canvasLabelColor("--muted", "#4d483f");
  context.font = canvasFont("400", 11 / k);
  context.textAlign = "center";
  context.textBaseline = "middle";
  context.fillText(job.text, 0, 0);
  context.restore();
}
