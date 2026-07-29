/** Draws the graph canvas and translates pointer gestures into node dragging or viewport panning. */

import {linkKey, nodeRadius, safeNodeColor} from "./model";
import type {Controller} from "./runtime";
import type {GraphEdge, ViewerNode} from "./types";

type Point = {x: number; y: number};
type NodeShape = "circle" | "diamond" | "square" | "triangle" | "hexagon";
type EdgeDrawInput = {
  controller: Controller;
  edge: GraphEdge;
  context: CanvasRenderingContext2D;
  worldPosition: CanvasHandlers["worldPosition"];
  labelColor: string;
};
type VisibleEdgeDrawInput = Pick<EdgeDrawInput, "controller" | "worldPosition">;

const NODE_SHAPE_RULES: ReadonlyArray<{pattern: RegExp; shape: Exclude<NodeShape, "circle">}> = [
  {pattern: /Vulnerability|AttackTechnique|ThreatGroup|CWE/, shape: "diamond"},
  {pattern: /TCCPermission|Entitlement|AuthRight|SandboxProfile/, shape: "hexagon"},
  {pattern: /User|Group/, shape: "triangle"},
  {pattern: /Host|Service|Daemon|LaunchAgent/, shape: "square"},
];

export interface CanvasHandlers {
  closeInspector(controller: Controller): void;
  hideContextMenu(controller: Controller): void;
  markDirty(controller: Controller): void;
  rebuildSpatial(controller: Controller): void;
  selectNode(controller: Controller, nodeId: string): void;
  showContextMenu(controller: Controller, event: MouseEvent, node: ViewerNode): void;
  worldPosition(controller: Controller, node: ViewerNode): Point;
}

export function canvasPoint(controller: Controller, event: MouseEvent): Point {
  const rect = controller.dom.canvas.getBoundingClientRect();
  const transform = controller.state.viewport.transform;
  return {
    x: (event.clientX - rect.left - transform.x) / transform.k,
    y: (event.clientY - rect.top - transform.y) / transform.k,
  };
}

export function nearestNode(controller: Controller, event: MouseEvent): ViewerNode | null {
  const point = canvasPoint(controller, event);
  return controller.spatial.findNearest(point.x, point.y, 20 / controller.state.viewport.transform.k);
}

export function drawNodeShape(context: CanvasRenderingContext2D, x: number, y: number, radius: number, kind: string): void {
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

export function drawFrame(controller: Controller, worldPosition: CanvasHandlers["worldPosition"]): void {
  const {state, dom} = controller;
  state.render.frameRequested = false;
  if (!state.render.dirty) return;
  state.render.dirty = false;
  const {context} = dom;
  context.save();
  context.clearRect(0, 0, state.viewport.width, state.viewport.height);
  context.translate(state.viewport.transform.x, state.viewport.transform.y);
  context.scale(state.viewport.transform.k, state.viewport.transform.k);
  drawEdges({controller, worldPosition});
  drawNodes(controller, worldPosition);
  context.restore();
}

export function canvasLabelColor(variable: "--muted" | "--subtle" | "--text", fallback: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(variable) || fallback;
}

export function drawEdges(input: VisibleEdgeDrawInput): void {
  const {controller, worldPosition} = input;
  const {state, dom: {context}} = controller;
  const labelColor = canvasLabelColor("--muted", "#aeb8c4");
  state.graph.links.forEach((edge, index) => {
    if (!state.render.visibleLinkIndexes.has(index)) return;
    drawEdge({controller, edge, context, worldPosition, labelColor});
  });
  context.globalAlpha = 1;
}

function drawEdge({controller, edge, context, worldPosition, labelColor}: EdgeDrawInput): void {
  const source = controller.state.graph.nodeById.get(edge.source);
  const target = controller.state.graph.nodeById.get(edge.target);
  if (!source || !target) return;
  const sourcePosition = worldPosition(controller, source);
  const targetPosition = worldPosition(controller, target);
  const onPath = controller.state.selection.path.result?.linkKeys.has(linkKey(edge)) === true;
  const segment = edgeSegment(sourcePosition, targetPosition, nodeRadius(controller.state.graph, source.id), nodeRadius(controller.state.graph, target.id));
  drawEdgeStroke(context, segment, onPath, edge.properties?._traversable === true);
  drawArrowhead(context, segment.source, segment.target, onPath ? "#6aafff" : "#8ea6bf");
  drawEdgeLabel({context, kind: edge.kind, source: sourcePosition, target: targetPosition, showLabels: controller.state.selection.showLabels, labelColor});
}

function drawEdgeStroke(context: CanvasRenderingContext2D, segment: {source: Point; target: Point}, onPath: boolean, traversable: boolean): void {
  context.beginPath();
  context.moveTo(segment.source.x, segment.source.y);
  context.lineTo(segment.target.x, segment.target.y);
  context.strokeStyle = onPath ? "#6aafff" : traversable ? "#8ea6bf" : "#59697a";
  context.globalAlpha = onPath ? 1 : 0.68;
  context.lineWidth = onPath ? 2.4 : 1.35;
  context.stroke();
}

export function edgeSegment(source: Point, target: Point, sourceRadius: number, targetRadius: number): {source: Point; target: Point} {
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const length = Math.max(1, Math.hypot(dx, dy));
  const ux = dx / length;
  const uy = dy / length;
  return {
    source: {x: source.x + ux * sourceRadius, y: source.y + uy * sourceRadius},
    target: {x: target.x - ux * (targetRadius + 5), y: target.y - uy * (targetRadius + 5)},
  };
}

export function drawArrowhead(context: CanvasRenderingContext2D, source: Point, target: Point, color: string): void {
  const angle = Math.atan2(target.y - source.y, target.x - source.x);
  context.beginPath();
  context.moveTo(target.x, target.y);
  context.lineTo(target.x - Math.cos(angle - Math.PI / 6) * 8, target.y - Math.sin(angle - Math.PI / 6) * 8);
  context.lineTo(target.x - Math.cos(angle + Math.PI / 6) * 8, target.y - Math.sin(angle + Math.PI / 6) * 8);
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

export function drawEdgeLabel({context, kind, source, target, showLabels, labelColor}: EdgeLabelInput): void {
  if (!showLabels || !kind) return;
  context.globalAlpha = 0.8;
  context.fillStyle = labelColor;
  context.font = "10px -apple-system, sans-serif";
  context.fillText(kind.replace(/^rs_/, ""), (source.x + target.x) / 2 + 4, (source.y + target.y) / 2 - 4);
}

export function drawNodes(controller: Controller, worldPosition: CanvasHandlers["worldPosition"]): void {
  const {state, dom: {context}} = controller;
  const labelColor = canvasLabelColor("--text", "#f3f6f9");
  for (const node of state.graph.nodes) {
    if (!state.render.visibleNodeIds.has(node.id)) continue;
    const position = worldPosition(controller, node);
    const radius = nodeRadius(state.graph, node.id);
    const selected = state.selection.selectedId === node.id || state.selection.pinnedId === node.id;
    if (selected) drawSelectionRings(context, position, radius);
    drawNodeShape(context, position.x, position.y, radius, node.kind);
    context.fillStyle = safeNodeColor(node.properties._color);
    context.fill();
    context.lineWidth = selected ? 2.5 : 1.5;
    context.strokeStyle = selected ? "#f3f6f9" : "rgba(243, 246, 249, .72)";
    context.stroke();
    drawNodeLabel(context, node, position, radius, state.selection.showLabels, labelColor);
  }
}

export function drawSelectionRings(context: CanvasRenderingContext2D, position: Point, radius: number): void {
  for (const [offset, alpha] of [[7, 0.9], [12, 0.45]] as const) {
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
  context.fillText(node.kind.replace(/^rs_/, "").replace(/([a-z])([A-Z])/g, "$1 $2"), position.x, position.y + radius + 32);
  context.textAlign = "start";
}

export function resizeCanvas(controller: Controller, fitViewport: () => void): void {
  const rect = controller.dom.graphContainer.getBoundingClientRect();
  const width = Math.max(1, Math.round(rect.width));
  const height = Math.max(1, Math.round(rect.height));
  const dpr = Math.max(1, window.devicePixelRatio || 1);
  controller.state.viewport.width = width;
  controller.state.viewport.height = height;
  controller.state.viewport.devicePixelRatio = dpr;
  controller.dom.canvas.width = Math.round(width * dpr);
  controller.dom.canvas.height = Math.round(height * dpr);
  controller.dom.context.setTransform(dpr, 0, 0, dpr, 0, 0);
  fitViewport();
}

/** Wires mutually exclusive node-drag and empty-space pan gestures, including click suppression after a drag. */
export function wireCanvas(controller: Controller, handlers: CanvasHandlers): void {
  bindClick(controller, handlers);
  bindWheel(controller, handlers);
  bindPointerDown(controller, handlers);
  bindPointerMove(controller, handlers);
  bindPointerEnd(controller);
  bindContextMenu(controller, handlers);
  bindPointerLeave(controller);
}

export function bindClick(controller: Controller, handlers: CanvasHandlers): void {
  controller.dom.canvas.addEventListener("click", (event) => {
    if (controller.state.pointer.suppressClick) {
      controller.state.pointer.suppressClick = false;
      return;
    }
    handlers.hideContextMenu(controller);
    const hit = nearestNode(controller, event);
    if (hit) handlers.selectNode(controller, hit.id);
    else if (!controller.state.selection.path.active) handlers.closeInspector(controller);
  });
}

export function bindWheel(controller: Controller, handlers: CanvasHandlers): void {
  controller.dom.canvas.addEventListener("wheel", (event) => {
    event.preventDefault();
    const rect = controller.dom.canvas.getBoundingClientRect();
    const screen = {x: event.clientX - rect.left, y: event.clientY - rect.top};
    const before = canvasPoint(controller, event);
    const transform = controller.state.viewport.transform;
    const nextK = Math.max(0.08, Math.min(4, transform.k * Math.exp((-event.deltaY * 15) / 10_000)));
    transform.x = screen.x - before.x * nextK;
    transform.y = screen.y - before.y * nextK;
    transform.k = nextK;
    handlers.markDirty(controller);
  }, {passive: false});
}

export function bindPointerDown(controller: Controller, handlers: CanvasHandlers): void {
  controller.dom.canvas.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    const point = canvasPoint(controller, event);
    const pointer = controller.state.pointer;
    pointer.mouseDown = {x: event.clientX, y: event.clientY};
    pointer.didDrag = false;
    pointer.suppressClick = false;
    const hit = nearestNode(controller, event);
    if (hit) beginDrag(controller, handlers, hit, point);
    else beginPan(controller, event);
    controller.dom.canvas.setPointerCapture(event.pointerId);
  });
}

export function beginDrag(controller: Controller, handlers: CanvasHandlers, node: ViewerNode, point: Point): void {
  const position = handlers.worldPosition(controller, node);
  controller.state.pointer.draggedId = node.id;
  controller.state.pointer.dragOffset = {x: point.x - position.x, y: point.y - position.y};
}

export function beginPan(controller: Controller, event: PointerEvent): void {
  controller.state.pointer.panning = true;
  controller.state.pointer.panStart = {x: event.clientX, y: event.clientY};
}

export function bindPointerMove(controller: Controller, handlers: CanvasHandlers): void {
  controller.dom.canvas.addEventListener("pointermove", (event) => {
    if (controller.state.pointer.draggedId || controller.state.pointer.panning) {
      moveActivePointer(controller, event, handlers);
      return;
    }
    updateHover(controller, event);
  });
}

export function moveActivePointer(controller: Controller, event: PointerEvent, handlers: CanvasHandlers): void {
  const pointer = controller.state.pointer;
  const dx = event.clientX - pointer.mouseDown.x;
  const dy = event.clientY - pointer.mouseDown.y;
  pointer.didDrag ||= dx * dx + dy * dy > 16;
  if (pointer.draggedId) moveNode(controller, event, handlers);
  else if (pointer.panning) moveViewport(controller, event, handlers);
  controller.dom.canvas.classList.add("grabbing");
}

export function moveNode(controller: Controller, event: PointerEvent, handlers: CanvasHandlers): void {
  const node = controller.state.graph.nodeById.get(controller.state.pointer.draggedId ?? "");
  if (!node) return;
  const point = canvasPoint(controller, event);
  node.x = point.x - controller.state.pointer.dragOffset.x;
  node.y = point.y - controller.state.pointer.dragOffset.y;
  handlers.rebuildSpatial(controller);
  handlers.markDirty(controller);
}

export function moveViewport(controller: Controller, event: PointerEvent, handlers: CanvasHandlers): void {
  const pointer = controller.state.pointer;
  controller.state.viewport.transform.x += event.clientX - pointer.panStart.x;
  controller.state.viewport.transform.y += event.clientY - pointer.panStart.y;
  pointer.panStart = {x: event.clientX, y: event.clientY};
  handlers.markDirty(controller);
}

export function updateHover(controller: Controller, event: PointerEvent): void {
  const hit = nearestNode(controller, event);
  controller.state.selection.hoveredId = hit?.id ?? null;
  const {tooltip} = controller.dom;
  tooltip.replaceChildren();
  if (!hit) {
    tooltip.classList.remove("visible");
    tooltip.hidden = true;
    return;
  }
  tooltip.append(tooltipLine("tt-label", hit.label ?? hit.id), tooltipLine("tt-kind", hit.kind));
  tooltip.style.left = `${event.offsetX + 16}px`;
  tooltip.style.top = `${event.offsetY - 8}px`;
  tooltip.hidden = false;
  tooltip.classList.add("visible");
  controller.dom.canvas.style.cursor = "pointer";
}

export function tooltipLine(className: string, text: string): HTMLDivElement {
  const result = document.createElement("div");
  result.className = className;
  result.textContent = text;
  return result;
}

export function bindPointerEnd(controller: Controller): void {
  const endPointer = (event: PointerEvent): void => {
    const pointer = controller.state.pointer;
    pointer.suppressClick = pointer.didDrag;
    pointer.draggedId = null;
    pointer.panning = false;
    pointer.didDrag = false;
    controller.dom.canvas.classList.remove("grabbing");
    controller.dom.canvas.style.cursor = "default";
    if (controller.dom.canvas.hasPointerCapture(event.pointerId)) controller.dom.canvas.releasePointerCapture(event.pointerId);
  };
  controller.dom.canvas.addEventListener("pointerup", endPointer);
  controller.dom.canvas.addEventListener("pointercancel", endPointer);
}

export function bindContextMenu(controller: Controller, handlers: CanvasHandlers): void {
  controller.dom.canvas.addEventListener("contextmenu", (event) => {
    const hit = nearestNode(controller, event);
    if (hit) handlers.showContextMenu(controller, event, hit);
    else handlers.hideContextMenu(controller);
  });
}

export function bindPointerLeave(controller: Controller): void {
  controller.dom.canvas.addEventListener("pointerleave", () => {
    if (controller.state.pointer.draggedId || controller.state.pointer.panning) return;
    controller.state.selection.hoveredId = null;
    controller.dom.tooltip.classList.remove("visible");
    controller.dom.tooltip.hidden = true;
    controller.dom.canvas.style.cursor = "default";
  });
}
