/** Exports the graph viewport as a PNG on an offscreen canvas, with a provenance footer. */

import { canvasFont, canvasLabelColor } from "./canvas-cache";
import { metadataTimestamp } from "./view";
import type { Controller } from "./runtime";

const FOOTER_HEIGHT = 32;
const FOOTER_PADDING = 12;

/** Exports on the ground color so dark-theme labels are not left on a transparent canvas. */
export function exportPng(controller: Controller): void {
  const source = controller.dom.canvas;
  const scale = source.clientWidth > 0 ? source.width / source.clientWidth : 1;
  const footer = Math.round(FOOTER_HEIGHT * scale);
  const surface = document.createElement("canvas");
  surface.width = source.width;
  surface.height = source.height + footer;
  const context = surface.getContext("2d");
  if (!context) return;
  context.fillStyle = canvasLabelColor("--ink-deep", "#ffffff");
  context.fillRect(0, 0, surface.width, surface.height);
  context.drawImage(source, 0, 0);
  drawFooter(context, controller, scale, source.height, footer);
  const link = document.createElement("a");
  link.download = `rootstock-graph-${exportName(controller)}.png`;
  link.href = surface.toDataURL("image/png");
  link.click();
}

export function footerText(controller: Controller): string {
  const metadata = controller.state.graph.payload.metadata ?? {};
  const hostname =
    typeof metadata.hostname === "string" && metadata.hostname ? metadata.hostname : "unknown host";
  const snapshot = metadataTimestamp(metadata.generated_at)?.toISOString() ?? "time not recorded";
  return `Rootstock · ${hostname} · ${snapshot} · modeled exposure, not confirmed compromise`;
}

function drawFooter(
  context: CanvasRenderingContext2D,
  controller: Controller,
  scale: number,
  top: number,
  height: number,
): void {
  const pad = FOOTER_PADDING * scale;
  const middle = top + height / 2;
  context.save();
  context.strokeStyle = canvasLabelColor("--edge-faint", "#334155");
  context.lineWidth = scale;
  context.beginPath();
  context.moveTo(0, top + scale / 2);
  context.lineTo(context.canvas.width, top + scale / 2);
  context.stroke();
  context.textBaseline = "middle";
  context.font = canvasFont("400", 12 * scale);
  const samples = drawLineSamples(context, scale, context.canvas.width - pad, middle);
  context.fillStyle = canvasLabelColor("--muted", "#475569");
  context.textAlign = "left";
  context.fillText(fitText(context, footerText(controller), samples - 2 * pad), pad, middle);
  context.restore();
}

/** Observed (solid) and inferred (dashed violet) samples, right-aligned; returns their left edge. */
function drawLineSamples(
  context: CanvasRenderingContext2D,
  scale: number,
  right: number,
  middle: number,
): number {
  const length = 28 * scale;
  const gap = 6 * scale;
  const entries = [
    {
      label: "Inferred",
      color: canvasLabelColor("--annotation", "#6d28d9"),
      dash: [7 * scale, 5 * scale],
    },
    { label: "Observed", color: canvasLabelColor("--edge", "#475569"), dash: [] as number[] },
  ];
  let x = right;
  context.textAlign = "right";
  for (const entry of entries) {
    context.fillStyle = canvasLabelColor("--muted", "#475569");
    context.fillText(entry.label, x, middle);
    x -= context.measureText(entry.label).width + gap;
    context.strokeStyle = entry.color;
    context.lineWidth = 1.3 * scale;
    context.setLineDash(entry.dash);
    context.beginPath();
    context.moveTo(x - length, middle);
    context.lineTo(x, middle);
    context.stroke();
    context.setLineDash([]);
    x -= length + 16 * scale;
  }
  return x;
}

function fitText(context: CanvasRenderingContext2D, text: string, width: number): string {
  if (context.measureText(text).width <= width) return text;
  let end = text.length;
  while (end > 1 && context.measureText(`${text.slice(0, end)}…`).width > width) end -= 1;
  return `${text.slice(0, end)}…`;
}

export function exportName(controller: Controller): string {
  const hostname = controller.state.graph.payload.metadata?.hostname;
  const name =
    typeof hostname === "string"
      ? hostname
          .toLowerCase()
          .replace(/[^a-z0-9-]+/g, "-")
          .replace(/^-+|-+$/g, "")
      : "";
  return name || "snapshot";
}
