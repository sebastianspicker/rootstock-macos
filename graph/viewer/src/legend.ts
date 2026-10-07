/** Renders the graph key: relationship inks, shapes, severity marks, and node-kind toggles. */

import { NODE_SHAPE_RULES } from "./canvas-drawing";
import type { NodeShape } from "./canvas-drawing";
import { element } from "./runtime";
import type { Controller } from "./runtime";
import type { GraphModel } from "./types";

const SVG_NS = "http://www.w3.org/2000/svg";
const opened = new WeakSet<Controller>();
const SHAPE_FAMILIES: Record<NodeShape, string> = {
  diamond: "",
  hexagon: "",
  triangle: "",
  square: "",
  circle: "Applications, files, and other kinds",
};

function svg(
  tag: string,
  attributes: Record<string, string>,
  children: Element[] = [],
): SVGElement {
  const result = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes)) result.setAttribute(name, value);
  for (const child of children) result.appendChild(child);
  return result;
}

function sample(children: Element[]): SVGElement {
  return svg(
    "svg",
    { class: "key-sample", viewBox: "0 0 36 12", width: "36", height: "12", "aria-hidden": "true" },
    children,
  );
}

function keyRow(mark: Element, label: string): HTMLLIElement {
  return element("li", { class: "key-row" }, [mark, element("span", { text: label })]);
}

function keySection(title: string, rows: HTMLElement[]): HTMLElement {
  return element("section", { class: "key-section" }, [
    element("h3", { text: title }),
    element("ul", {}, rows),
  ]);
}

function relationshipRows(): HTMLLIElement[] {
  const line = (className: string): SVGElement =>
    svg("line", { class: `key-line ${className}`, x1: "2", y1: "6", x2: "34", y2: "6" });
  return [
    keyRow(sample([line("observed")]), "Observed"),
    keyRow(sample([line("inferred")]), "Inferred (modeled)"),
    keyRow(sample([line("on-path")]), "On modeled path"),
    keyRow(
      sample([line("observed"), svg("path", { class: "key-head", d: "M34 6 26 2v8z" })]),
      "Traversable direction",
    ),
    keyRow(
      sample([
        svg("line", { class: "key-line observed", x1: "2", y1: "6", x2: "28", y2: "6" }),
        svg("circle", { class: "key-end", cx: "31", cy: "6", r: "3" }),
      ]),
      "Not traversable",
    ),
  ];
}

/** Polygon points use the same geometry as the canvas so the key matches what is drawn. */
function shapePoints(shape: Exclude<NodeShape, "circle" | "square">): string {
  const sides = shape === "diamond" ? 4 : shape === "triangle" ? 3 : 6;
  const rotation = shape === "triangle" ? -Math.PI / 2 : 0;
  return Array.from({ length: sides }, (_, index) => {
    const angle = rotation + (index / sides) * Math.PI * 2;
    return `${(8 + Math.cos(angle) * 6).toFixed(2)},${(8 + Math.sin(angle) * 6).toFixed(2)}`;
  }).join(" ");
}

function shapeMark(shape: NodeShape): SVGElement {
  const attributes = { class: "key-shape" };
  const body =
    shape === "circle"
      ? svg("circle", { ...attributes, cx: "8", cy: "8", r: "6" })
      : shape === "square"
        ? svg("rect", { ...attributes, x: "2.5", y: "2.5", width: "11", height: "11" })
        : svg("polygon", { ...attributes, points: shapePoints(shape) });
  return svg(
    "svg",
    { class: "key-sample", viewBox: "0 0 16 16", width: "16", height: "16", "aria-hidden": "true" },
    [body],
  );
}

function shapeRows(): HTMLLIElement[] {
  const rows = NODE_SHAPE_RULES.map((rule) =>
    keyRow(
      shapeMark(rule.shape),
      SHAPE_FAMILIES[rule.shape] ||
        rule.pattern.source
          .split("|")
          .map((name) => name.replace(/([a-z])([A-Z])/g, "$1 $2"))
          .join(", "),
    ),
  );
  rows.push(keyRow(shapeMark("circle"), SHAPE_FAMILIES.circle));
  return rows;
}

function severityRows(): HTMLLIElement[] {
  const rows = ["critical", "high", "medium", "low"].map((risk) =>
    keyRow(
      element("span", { class: `node-symbol node-severity-${risk}`, "aria-hidden": "true" }),
      risk.charAt(0).toUpperCase() + risk.slice(1),
    ),
  );
  rows.push(keyRow(element("span", { class: "key-owned", "aria-hidden": "true" }), "Owned"));
  return rows;
}

/** One dot per kind; a kind whose nodes carry several colours shows them as a segmented dot. */
export function kindSwatch(colors: readonly string[], hideFromAssistiveTech: boolean): HTMLElement {
  const dot = element("span", { class: "color-dot" });
  const [first] = colors;
  if (colors.length < 2) {
    if (first) dot.style.background = first;
    if (hideFromAssistiveTech) dot.setAttribute("aria-hidden", "true");
    return dot;
  }
  const size = 100 / colors.length;
  const stops = colors.map((color, index) => `${color} ${index * size}% ${(index + 1) * size}%`);
  dot.classList.add("mixed");
  dot.style.background = `conic-gradient(${stops.join(", ")})`;
  dot.setAttribute("aria-hidden", "true");
  const note = `${colors.length} colours in this kind`;
  return element("span", { class: "kind-swatch", title: note }, [
    dot,
    element("span", { class: "sr-only", text: note }),
  ]);
}

function kindRows(controller: Controller, rebuild: () => void): HTMLLIElement[] {
  const active = controller.state.filters.activeNodeKinds;
  return [...controller.state.graph.kindMeta.entries()]
    .sort((left, right) => right[1].count - left[1].count)
    .map(([kind, info]) => {
      const dot = kindSwatch(info.colors, true);
      const toggle = element(
        "button",
        {
          type: "button",
          class: "key-kind",
          "data-kind": kind,
          "aria-pressed": String(active.has(kind)),
        },
        [
          dot,
          element("span", { text: info.label }),
          element("span", { class: "filter-count", text: String(info.count) }),
        ],
      );
      toggle.addEventListener("click", () => {
        if (active.has(kind)) active.delete(kind);
        else active.add(kind);
        rebuild();
        controller.actions.updateVisibility(controller);
        controller.dom.graphKeyBody
          .querySelector<HTMLButtonElement>(`button[data-kind="${CSS.escape(kind)}"]`)
          ?.focus();
      });
      return element("li", {}, [toggle]);
    });
}

function shouldOpen(controller: Controller, graph: GraphModel): boolean {
  if (opened.has(controller) || graph.kindMeta.size < 2) return false;
  opened.add(controller);
  return true;
}

/** Re-rendered with the filters so it follows graph replacement and kind toggles. */
export function renderGraphKey(controller: Controller, rebuild: () => void): void {
  const { graphKey, graphKeyBody } = controller.dom;
  graphKeyBody.replaceChildren(
    keySection("Relationships", relationshipRows()),
    keySection("Shapes", shapeRows()),
    keySection("Severity", severityRows()),
    keySection("Node kinds", kindRows(controller, rebuild)),
  );
  if (shouldOpen(controller, controller.state.graph)) graphKey.open = true;
}
