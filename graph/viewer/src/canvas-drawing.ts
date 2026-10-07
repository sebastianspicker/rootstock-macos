/** Draw graph primitives with conservative viewport bounds. */
import {
  around,
  intersects,
  viewportBounds,
  textWidth,
  canvasFont,
  canvasLabelColor,
} from "./canvas-cache";
import type { CanvasColorToken } from "./canvas-cache";
import { nodeRadius, safeNodeColor } from "./model";
import type { Controller } from "./runtime";
import type { ViewerNode } from "./types";
import type { CanvasHandlers } from "./canvas";
export {
  drawEdges,
  drawEdgeLabel,
  drawArrowhead,
  edgeSegment,
  edgeStyle,
  edgeIsInferred,
  edgeIsTraversable,
} from "./canvas-edges";
type Point = { x: number; y: number };

export type NodeShape = "circle" | "diamond" | "square" | "triangle" | "hexagon";

const LABEL_MAX_CHARACTERS = 28;
const LABEL_DENSITY_ZOOM = 0.45;
const SEVERITY_TOKENS: Record<string, CanvasColorToken> = {
  critical: "--critical",
  high: "--high",
  medium: "--medium",
  low: "--low",
};

export const NODE_SHAPE_RULES: ReadonlyArray<{
  pattern: RegExp;
  shape: Exclude<NodeShape, "circle">;
}> = [
  { pattern: /Vulnerability|AttackTechnique|ThreatGroup|CWE/, shape: "diamond" },
  { pattern: /TCCPermission|Entitlement|AuthRight|SandboxProfile/, shape: "hexagon" },
  { pattern: /User|Group/, shape: "triangle" },
  { pattern: /Host|Service|Daemon|LaunchAgent/, shape: "square" },
];

export function drawNodeShape(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  radius: number,
  kind: string,
): void {
  const shape = nodeShape(kind);
  context.beginPath();
  if (shape === "circle") context.arc(x, y, radius, 0, Math.PI * 2);
  else if (shape === "square") context.rect(x - radius, y - radius, radius * 2, radius * 2);
  else drawPolygon(context, x, y, radius, shape);
}

export function nodeShape(kind: string): NodeShape {
  return NODE_SHAPE_RULES.find((rule) => rule.pattern.test(kind))?.shape ?? "circle";
}

export function drawPolygon(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  radius: number,
  shape: "diamond" | "triangle" | "hexagon",
): void {
  const sides = shape === "diamond" ? 4 : shape === "triangle" ? 3 : 6;
  // A diamond is a square standing on a vertex, so it needs no rotation from angle 0.
  const rotation = shape === "triangle" ? -Math.PI / 2 : 0;
  for (let index = 0; index < sides; index += 1) {
    const angle = rotation + (index / sides) * Math.PI * 2;
    const px = x + Math.cos(angle) * radius;
    const py = y + Math.sin(angle) * radius;
    if (index === 0) context.moveTo(px, py);
    else context.lineTo(px, py);
  }
  context.closePath();
}

type NodeFrame = { node: ViewerNode; position: Point; radius: number };

/** Shapes first, then labels and badges, so later nodes never paint over earlier labels. */
export function drawNodes(
  controller: Controller,
  worldPosition: CanvasHandlers["worldPosition"],
): void {
  const { state } = controller;
  const { context } = controller.dom;
  const frames: NodeFrame[] = [];
  for (const node of state.graph.nodes) {
    if (!state.render.visibleNodeIds.has(node.id)) continue;
    const frame = {
      node,
      position: worldPosition(controller, node),
      radius: nodeRadius(state.graph, node.id),
    };
    frames.push(frame);
    drawVisibleNodeShape(controller, frame);
  }
  if (state.selection.showLabels)
    for (const frame of frames)
      if (labelAllowed(controller, frame.node.id) && nodeLabelIntersects(controller, frame))
        drawNodeLabel(controller, frame);
  for (const frame of frames) drawNodeBadges(controller, frame);
  context.globalAlpha = 1;
  context.setLineDash([]);
}

function isSelected(controller: Controller, nodeId: string): boolean {
  const { selectedId, pinnedId } = controller.state.selection;
  return selectedId === nodeId || pinnedId === nodeId;
}

function isOnPath(controller: Controller, nodeId: string): boolean {
  return controller.state.selection.path.result?.nodeIds.has(nodeId) === true;
}

/** In Graph, a retained modeled path keeps full weight while everything else recedes. */
function nodeAlpha(controller: Controller, nodeId: string): number {
  const { workspace, selection } = controller.state;
  return workspace === "graph" && selection.path.result && !isOnPath(controller, nodeId) ? 0.15 : 1;
}

/** Below the density zoom only the nodes under attention keep their labels. */
function labelAllowed(controller: Controller, nodeId: string): boolean {
  if (controller.state.viewport.transform.k >= LABEL_DENSITY_ZOOM) return true;
  return (
    isSelected(controller, nodeId) ||
    controller.state.selection.hoveredId === nodeId ||
    isOnPath(controller, nodeId)
  );
}

function drawVisibleNodeShape(controller: Controller, { node, position, radius }: NodeFrame): void {
  const { context } = controller.dom;
  const k = controller.state.viewport.transform.k;
  if (!intersects(viewportBounds(controller), around(position.x, position.y, radius + 14))) return;
  const selected = isSelected(controller, node.id);
  context.globalAlpha = nodeAlpha(controller, node.id);
  if (selected) drawSelectionRings(context, position, radius, k);
  if (controller.state.selection.hoveredId === node.id) drawHoverRing(context, position, radius, k);
  drawNodeShape(context, position.x, position.y, radius, node.kind);
  context.fillStyle = safeNodeColor(node.properties._color);
  context.fill();
  // Data colors can be pale on a light ground; a text-colored outline keeps every node distinguishable.
  context.lineWidth = (selected ? 2.5 : 1.25) / k;
  context.strokeStyle = canvasLabelColor("--text", "#0f172a");
  context.stroke();
  context.globalAlpha = 1;
}

function drawHoverRing(
  context: CanvasRenderingContext2D,
  position: Point,
  radius: number,
  k: number,
): void {
  context.beginPath();
  context.arc(position.x, position.y, radius + 4 / k, 0, Math.PI * 2);
  context.lineWidth = 1 / k;
  context.strokeStyle = canvasLabelColor("--muted", "#475569");
  context.stroke();
}

export function displayCanvasKind(kind: string): string {
  return kind.replace(/^rs_/, "").replace(/([a-z])([A-Z])/g, "$1 $2");
}

export function nodeSeverity(node: ViewerNode): string {
  const value = node.properties.risk_level ?? node.properties.severity;
  const risk = typeof value === "string" ? value.toLowerCase() : "";
  return SEVERITY_TOKENS[risk] ? risk : "";
}

export function truncateLabel(label: string, limit = LABEL_MAX_CHARACTERS): string {
  return label.length > limit ? `${label.slice(0, limit - 1)}…` : label;
}

function nodeLabelIntersects(
  controller: Controller,
  { node, position, radius }: NodeFrame,
): boolean {
  const context = controller.dom.context;
  const width = Math.max(
    textWidth(context, canvasFont("600", 16), truncateLabel(node.label ?? node.id)),
    textWidth(context, canvasFont("400", 12), `${displayCanvasKind(node.kind)} · critical`),
  );
  return intersects(viewportBounds(controller), {
    left: position.x - width / 2 - 8,
    right: position.x + width / 2 + 8,
    top: position.y + radius - 8,
    bottom: position.y + radius + 48,
  });
}

export function drawSelectionRings(
  context: CanvasRenderingContext2D,
  position: Point,
  radius: number,
  k = 1,
): void {
  for (const [offset, alpha] of [
    [7, 0.9],
    [12, 0.45],
  ] as const) {
    context.beginPath();
    context.arc(position.x, position.y, radius + offset / k, 0, Math.PI * 2);
    context.globalAlpha = alpha;
    context.strokeStyle = canvasLabelColor("--text", "#0f172a");
    context.lineWidth = (offset === 7 ? 2 : 1) / k;
    context.stroke();
  }
  context.globalAlpha = 1;
}

/** Text with a ground-colored halo so labels stay legible where they cross relationships. */
function haloText(
  context: CanvasRenderingContext2D,
  text: string,
  x: number,
  y: number,
  k: number,
): void {
  context.lineWidth = 3 / k;
  context.lineJoin = "round";
  context.strokeStyle = canvasLabelColor("--ink-deep", "#ffffff");
  context.strokeText(text, x, y);
  context.fillText(text, x, y);
}

/** Two lines: the label, then `Kind · severity` with the severity word in its pigment. */
export function drawNodeLabel(controller: Controller, { node, position, radius }: NodeFrame): void {
  const { context } = controller.dom;
  const k = controller.state.viewport.transform.k;
  context.globalAlpha = nodeAlpha(controller, node.id);
  context.textAlign = "center";
  context.fillStyle = canvasLabelColor("--text", "#0f172a");
  context.font = canvasFont("600", 16);
  haloText(context, truncateLabel(node.label ?? node.id), position.x, position.y + radius + 18, k);
  const kind = displayCanvasKind(node.kind);
  const severity = nodeSeverity(node);
  const font = canvasFont("400", 12);
  const kindText = severity ? `${kind} · ` : kind;
  const kindWidth = textWidth(context, font, kindText);
  const total = kindWidth + (severity ? textWidth(context, font, severity) : 0);
  const y = position.y + radius + 32;
  context.font = font;
  context.textAlign = "start";
  context.fillStyle = canvasLabelColor("--subtle", "#5b6678");
  haloText(context, kindText, position.x - total / 2, y, k);
  const token = SEVERITY_TOKENS[severity];
  if (token) {
    context.fillStyle = canvasLabelColor(token, "#5b6678");
    haloText(context, severity, position.x - total / 2 + kindWidth, y, k);
  }
  context.globalAlpha = 1;
}

/** Numbered modeled-path steps at the top left; an owned flag at the top right. */
function drawNodeBadges(controller: Controller, { node, position, radius }: NodeFrame): void {
  const { context } = controller.dom;
  const k = controller.state.viewport.transform.k;
  const corner = radius * 0.75;
  if (!intersects(viewportBounds(controller), around(position.x, position.y, radius + 12 / k)))
    return;
  const step = controller.state.selection.path.result?.orderedNodeIds.indexOf(node.id) ?? -1;
  if (step >= 0) {
    const center = { x: position.x - corner, y: position.y - corner };
    context.beginPath();
    context.arc(center.x, center.y, 9 / k, 0, Math.PI * 2);
    context.fillStyle = canvasLabelColor("--path", "#6d28d9");
    context.fill();
    context.fillStyle = canvasLabelColor("--ink", "#f4f6f9");
    context.font = canvasFont("700", 11 / k);
    context.textAlign = "center";
    context.textBaseline = "middle";
    context.fillText(String(step + 1), center.x, center.y + 0.5 / k);
    context.textAlign = "start";
    context.textBaseline = "alphabetic";
  }
  if (node.properties.owned === true) {
    const size = 8 / k;
    context.fillStyle = canvasLabelColor("--text", "#0f172a");
    context.fillRect(position.x + corner - size / 2, position.y - corner - size / 2, size, size);
  }
}
