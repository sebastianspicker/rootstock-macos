/** Draw graph primitives with conservative viewport bounds. */
import { around, intersects, viewportBounds, textWidth, canvasLabelColor } from "./canvas-cache";
import { linkKey, nodeRadius, safeNodeColor } from "./model";
import type { Controller } from "./runtime";
import type { GraphEdge, ViewerNode } from "./types";
import type { CanvasHandlers } from "./canvas";
type Point = { x: number; y: number };

type NodeShape = "circle" | "diamond" | "square" | "triangle" | "hexagon";
type EdgeDrawInput = {
  controller: Controller;
  edge: GraphEdge;
  context: CanvasRenderingContext2D;
  worldPosition: CanvasHandlers["worldPosition"];
  labelColor: string;
};
type VisibleEdgeDrawInput = Pick<EdgeDrawInput, "controller" | "worldPosition">;

const NODE_SHAPE_RULES: ReadonlyArray<{ pattern: RegExp; shape: Exclude<NodeShape, "circle"> }> = [
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
  const rotation = shape === "diamond" ? Math.PI / 4 : shape === "triangle" ? -Math.PI / 2 : 0;
  for (let index = 0; index < sides; index += 1) {
    const angle = rotation + (index / sides) * Math.PI * 2;
    const px = x + Math.cos(angle) * radius;
    const py = y + Math.sin(angle) * radius;
    if (index === 0) context.moveTo(px, py);
    else context.lineTo(px, py);
  }
  context.closePath();
}

export function drawEdges(input: VisibleEdgeDrawInput): void {
  const { controller, worldPosition } = input;
  const {
    state,
    dom: { context },
  } = controller;
  const labelColor = canvasLabelColor("--muted", "#aeb8c4");
  state.graph.links.forEach((edge, index) => {
    if (!state.render.visibleLinkIndexes.has(index)) return;
    drawEdge({ controller, edge, context, worldPosition, labelColor });
  });
  context.globalAlpha = 1;
}

function drawEdge({ controller, edge, context, worldPosition, labelColor }: EdgeDrawInput): void {
  const source = controller.state.graph.nodeById.get(edge.source);
  const target = controller.state.graph.nodeById.get(edge.target);
  if (!source || !target) return;
  const sourcePosition = worldPosition(controller, source);
  const targetPosition = worldPosition(controller, target);
  const onPath = controller.state.selection.path.result?.linkKeys.has(linkKey(edge)) === true;
  const segment = edgeSegment(
    sourcePosition,
    targetPosition,
    nodeRadius(controller.state.graph, source.id),
    nodeRadius(controller.state.graph, target.id),
  );
  const viewport = viewportBounds(controller);
  const lineBounds = {
    left: Math.min(segment.source.x, segment.target.x) - 10,
    right: Math.max(segment.source.x, segment.target.x) + 10,
    top: Math.min(segment.source.y, segment.target.y) - 10,
    bottom: Math.max(segment.source.y, segment.target.y) + 10,
  };
  if (intersects(viewport, lineBounds)) {
    drawEdgeStroke(context, segment, onPath, edge.properties?._traversable === true);
    drawArrowhead(context, segment.source, segment.target, onPath ? "#6aafff" : "#8ea6bf");
  }
  drawVisibleEdgeLabel(controller, edge, sourcePosition, targetPosition, labelColor);
}

function drawVisibleEdgeLabel(
  controller: Controller,
  edge: GraphEdge,
  sourcePosition: Point,
  targetPosition: Point,
  labelColor: string,
): void {
  const { context } = controller.dom;
  const viewport = viewportBounds(controller);
  if (controller.state.selection.showLabels) {
    const x = (sourcePosition.x + targetPosition.x) / 2 + 4;
    const y = (sourcePosition.y + targetPosition.y) / 2 - 4;
    const width = textWidth(
      context,
      "10px -apple-system, sans-serif",
      edge.kind.replace(/^rs_/, ""),
    );
    if (intersects(viewport, { left: x - 8, right: x + width + 8, top: y - 20, bottom: y + 10 }))
      drawEdgeLabel({
        context,
        kind: edge.kind,
        source: sourcePosition,
        target: targetPosition,
        showLabels: true,
        labelColor,
      });
  }
}

function drawEdgeStroke(
  context: CanvasRenderingContext2D,
  segment: { source: Point; target: Point },
  onPath: boolean,
  traversable: boolean,
): void {
  context.beginPath();
  context.moveTo(segment.source.x, segment.source.y);
  context.lineTo(segment.target.x, segment.target.y);
  context.strokeStyle = onPath ? "#6aafff" : traversable ? "#8ea6bf" : "#59697a";
  context.globalAlpha = onPath ? 1 : 0.68;
  context.lineWidth = onPath ? 2.4 : 1.35;
  context.stroke();
}

export function edgeSegment(
  source: Point,
  target: Point,
  sourceRadius: number,
  targetRadius: number,
): { source: Point; target: Point } {
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const length = Math.max(1, Math.hypot(dx, dy));
  const ux = dx / length;
  const uy = dy / length;
  return {
    source: { x: source.x + ux * sourceRadius, y: source.y + uy * sourceRadius },
    target: { x: target.x - ux * (targetRadius + 5), y: target.y - uy * (targetRadius + 5) },
  };
}

export function drawArrowhead(
  context: CanvasRenderingContext2D,
  source: Point,
  target: Point,
  color: string,
): void {
  const angle = Math.atan2(target.y - source.y, target.x - source.x);
  context.beginPath();
  context.moveTo(target.x, target.y);
  context.lineTo(
    target.x - Math.cos(angle - Math.PI / 6) * 8,
    target.y - Math.sin(angle - Math.PI / 6) * 8,
  );
  context.lineTo(
    target.x - Math.cos(angle + Math.PI / 6) * 8,
    target.y - Math.sin(angle + Math.PI / 6) * 8,
  );
  context.closePath();
  context.fillStyle = color;
  context.fill();
}

type EdgeLabelInput = {
  context: CanvasRenderingContext2D;
  kind: string;
  source: Point;
  target: Point;
  showLabels: boolean;
  labelColor: string;
};

export function drawEdgeLabel({
  context,
  kind,
  source,
  target,
  showLabels,
  labelColor,
}: EdgeLabelInput): void {
  if (!showLabels || !kind) return;
  context.globalAlpha = 0.8;
  context.fillStyle = labelColor;
  context.font = "10px -apple-system, sans-serif";
  context.fillText(
    kind.replace(/^rs_/, ""),
    (source.x + target.x) / 2 + 4,
    (source.y + target.y) / 2 - 4,
  );
}

export function drawNodes(
  controller: Controller,
  worldPosition: CanvasHandlers["worldPosition"],
): void {
  const {
    state,
    dom: { context },
  } = controller;
  const labelColor = canvasLabelColor("--text", "#f3f6f9");
  for (const node of state.graph.nodes) {
    if (!state.render.visibleNodeIds.has(node.id)) continue;
    const position = worldPosition(controller, node);
    const radius = nodeRadius(state.graph, node.id);
    drawVisibleNodeShape(controller, node, position, radius);
    if (state.selection.showLabels && nodeLabelIntersects(controller, node, position, radius))
      drawNodeLabel(context, node, position, radius, true, labelColor);
  }
}

function drawVisibleNodeShape(
  controller: Controller,
  node: ViewerNode,
  position: Point,
  radius: number,
): void {
  const {
    state,
    dom: { context },
  } = controller;
  const selected = state.selection.selectedId === node.id || state.selection.pinnedId === node.id;
  if (intersects(viewportBounds(controller), around(position.x, position.y, radius + 14))) {
    if (selected) drawSelectionRings(context, position, radius);
    drawNodeShape(context, position.x, position.y, radius, node.kind);
    context.fillStyle = safeNodeColor(node.properties._color);
    context.fill();
    context.lineWidth = selected ? 2.5 : 1.5;
    context.strokeStyle = selected ? "#f3f6f9" : "rgba(243, 246, 249, .72)";
    context.stroke();
  }
}

function nodeLabelIntersects(
  controller: Controller,
  node: ViewerNode,
  position: Point,
  radius: number,
): boolean {
  const context = controller.dom.context;
  const width = Math.max(
    textWidth(context, "600 16px -apple-system, sans-serif", node.label ?? node.id),
    textWidth(
      context,
      "12px -apple-system, sans-serif",
      node.kind.replace(/^rs_/, "").replace(/([a-z])([A-Z])/g, "$1 $2"),
    ),
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
): void {
  for (const [offset, alpha] of [
    [7, 0.9],
    [12, 0.45],
  ] as const) {
    context.beginPath();
    context.arc(position.x, position.y, radius + offset, 0, Math.PI * 2);
    context.strokeStyle = `rgba(106, 175, 255, ${alpha})`;
    context.lineWidth = offset === 7 ? 3 : 2;
    context.stroke();
  }
}

export function drawNodeLabel(
  context: CanvasRenderingContext2D,
  node: ViewerNode,
  position: Point,
  radius: number,
  showLabels: boolean,
  labelColor: string,
): void {
  if (!showLabels) return;
  context.fillStyle = labelColor;
  context.font = "600 16px -apple-system, sans-serif";
  context.textAlign = "center";
  context.fillText(node.label ?? node.id, position.x, position.y + radius + 18);
  context.fillStyle = canvasLabelColor("--subtle", "#8c99a8");
  context.font = "12px -apple-system, sans-serif";
  context.fillText(
    node.kind.replace(/^rs_/, "").replace(/([a-z])([A-Z])/g, "$1 $2"),
    position.x,
    position.y + radius + 32,
  );
  context.textAlign = "start";
}
