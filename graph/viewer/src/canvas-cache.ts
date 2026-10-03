/** Conservative world-space culling and reusable canvas style/text lookups. */
import type { Controller } from "./runtime";

export interface Bounds {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

export function viewportBounds(controller: Controller): Bounds {
  const {
    width,
    height,
    transform: { x, y, k },
  } = controller.state.viewport;
  return { left: -x / k, top: -y / k, right: (width - x) / k, bottom: (height - y) / k };
}

export function intersects(a: Bounds, b: Bounds): boolean {
  return a.left <= b.right && a.right >= b.left && a.top <= b.bottom && a.bottom >= b.top;
}

export function around(x: number, y: number, width: number, height = width): Bounds {
  return { left: x - width, right: x + width, top: y - height, bottom: y + height };
}

const colors = new Map<string, string>();
const widths = new WeakMap<CanvasRenderingContext2D, Map<string, number>>();

export function invalidateCanvasColors(): void {
  colors.clear();
}

export function canvasLabelColor(
  variable: "--muted" | "--subtle" | "--text" | "--ink" | "--path" | "--edge" | "--edge-faint",
  fallback: string,
): string {
  let color = colors.get(variable);
  if (!color) {
    color = getComputedStyle(document.documentElement).getPropertyValue(variable) || fallback;
    colors.set(variable, color);
  }
  return color;
}

export function textWidth(context: CanvasRenderingContext2D, font: string, text: string): number {
  let cache = widths.get(context);
  if (!cache) {
    cache = new Map();
    widths.set(context, cache);
  }
  const key = `${font}:${text}`;
  let width = cache.get(key);
  if (width === undefined) {
    context.font = font;
    const metrics = context.measureText(text);
    width = Math.max(
      metrics.width,
      Math.abs(metrics.actualBoundingBoxLeft) + Math.abs(metrics.actualBoundingBoxRight),
    );
    if (cache.size >= 20_000) cache.clear();
    cache.set(key, width);
  }
  return width;
}
