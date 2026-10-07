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

export type CanvasColorToken =
  | "--muted"
  | "--subtle"
  | "--text"
  | "--ink"
  | "--ink-deep"
  | "--pane"
  | "--path"
  | "--annotation"
  | "--edge"
  | "--edge-faint"
  | "--critical"
  | "--high"
  | "--medium"
  | "--low";

export function canvasLabelColor(variable: CanvasColorToken, fallback: string): string {
  return cssToken(variable, fallback);
}

/** Canvas fonts cannot use CSS variables, so the UI family is resolved once like the colors. */
export function canvasFont(weight: string, size: number): string {
  return `${weight} ${size}px ${cssToken("--font-ui", "-apple-system, sans-serif")}`;
}

function cssToken(variable: string, fallback: string): string {
  let token = colors.get(variable);
  if (!token) {
    token =
      getComputedStyle(document.documentElement).getPropertyValue(variable).trim() || fallback;
    colors.set(variable, token);
  }
  return token;
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
