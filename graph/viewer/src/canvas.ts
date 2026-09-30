import { drawEdges, drawNodes } from "./canvas-drawing";
export {
  drawEdges,
  drawNodes,
  drawNodeShape,
  nodeShape,
  drawPolygon,
  edgeSegment,
  drawArrowhead,
  drawEdgeLabel,
  drawSelectionRings,
  drawNodeLabel,
} from "./canvas-drawing";
export { canvasLabelColor } from "./canvas-cache";
/** Draws the graph canvas and translates pointer gestures into node dragging or viewport panning. */

import type { Controller } from "./runtime";
import type { ViewerNode } from "./types";

type Point = { x: number; y: number };
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
  return controller.spatial.findNearest(
    point.x,
    point.y,
    20 / controller.state.viewport.transform.k,
  );
}

export function drawFrame(
  controller: Controller,
  worldPosition: CanvasHandlers["worldPosition"],
): void {
  const { state, dom } = controller;
  state.render.frameRequested = false;
  if (!state.render.dirty) return;
  state.render.dirty = false;
  const { context } = dom;
  context.save();
  context.clearRect(0, 0, state.viewport.width, state.viewport.height);
  context.translate(state.viewport.transform.x, state.viewport.transform.y);
  context.scale(state.viewport.transform.k, state.viewport.transform.k);
  drawEdges({ controller, worldPosition });
  drawNodes(controller, worldPosition);
  context.restore();
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
  controller.dom.canvas.addEventListener(
    "wheel",
    (event) => {
      event.preventDefault();
      const rect = controller.dom.canvas.getBoundingClientRect();
      const screen = { x: event.clientX - rect.left, y: event.clientY - rect.top };
      const before = canvasPoint(controller, event);
      const transform = controller.state.viewport.transform;
      const nextK = Math.max(
        0.08,
        Math.min(4, transform.k * Math.exp((-event.deltaY * 15) / 10_000)),
      );
      transform.x = screen.x - before.x * nextK;
      transform.y = screen.y - before.y * nextK;
      transform.k = nextK;
      handlers.markDirty(controller);
    },
    { passive: false },
  );
}

export function bindPointerDown(controller: Controller, handlers: CanvasHandlers): void {
  controller.dom.canvas.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    const point = canvasPoint(controller, event);
    const pointer = controller.state.pointer;
    pointer.mouseDown = { x: event.clientX, y: event.clientY };
    pointer.didDrag = false;
    pointer.suppressClick = false;
    const hit = nearestNode(controller, event);
    if (hit) beginDrag(controller, handlers, hit, point);
    else beginPan(controller, event);
    controller.dom.canvas.setPointerCapture(event.pointerId);
  });
}

export function beginDrag(
  controller: Controller,
  handlers: CanvasHandlers,
  node: ViewerNode,
  point: Point,
): void {
  const position = handlers.worldPosition(controller, node);
  controller.state.pointer.draggedId = node.id;
  controller.state.pointer.dragOffset = { x: point.x - position.x, y: point.y - position.y };
}

export function beginPan(controller: Controller, event: PointerEvent): void {
  controller.state.pointer.panning = true;
  controller.state.pointer.panStart = { x: event.clientX, y: event.clientY };
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

export function moveActivePointer(
  controller: Controller,
  event: PointerEvent,
  handlers: CanvasHandlers,
): void {
  const pointer = controller.state.pointer;
  const dx = event.clientX - pointer.mouseDown.x;
  const dy = event.clientY - pointer.mouseDown.y;
  pointer.didDrag ||= dx * dx + dy * dy > 16;
  if (pointer.draggedId) moveNode(controller, event, handlers);
  else if (pointer.panning) moveViewport(controller, event, handlers);
  controller.dom.canvas.classList.add("grabbing");
}

export function moveNode(
  controller: Controller,
  event: PointerEvent,
  handlers: CanvasHandlers,
): void {
  const node = controller.state.graph.nodeById.get(controller.state.pointer.draggedId ?? "");
  if (!node) return;
  const point = canvasPoint(controller, event);
  node.x = point.x - controller.state.pointer.dragOffset.x;
  node.y = point.y - controller.state.pointer.dragOffset.y;
  controller.spatial.update(node);
  handlers.markDirty(controller);
}

export function moveViewport(
  controller: Controller,
  event: PointerEvent,
  handlers: CanvasHandlers,
): void {
  const pointer = controller.state.pointer;
  controller.state.viewport.transform.x += event.clientX - pointer.panStart.x;
  controller.state.viewport.transform.y += event.clientY - pointer.panStart.y;
  pointer.panStart = { x: event.clientX, y: event.clientY };
  handlers.markDirty(controller);
}

export function updateHover(controller: Controller, event: PointerEvent): void {
  const hit = nearestNode(controller, event);
  controller.state.selection.hoveredId = hit?.id ?? null;
  const { tooltip } = controller.dom;
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
    if (controller.dom.canvas.hasPointerCapture(event.pointerId))
      controller.dom.canvas.releasePointerCapture(event.pointerId);
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
