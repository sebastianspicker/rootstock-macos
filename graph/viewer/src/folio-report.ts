import { snapshotHtml } from "./folio-snapshot-html";
/** Report preparation and download payload validation, separate from investigation state. */
import type { GraphModel, ViewerNode } from "./types";
import type { Controller } from "./runtime";
import { apiFetch } from "./live";
import { snapshotSummary, sourceName } from "./folio-data";
import { el, intro, appIdentity, para, warning, heading } from "./folio-ui";
export interface ReportView {
  live: boolean;
  graph: GraphModel;
  selected: ViewerNode | undefined;
  busy: boolean;
  format: "markdown" | "html";
  filename: string;
  render(): void;
}
export function renderReport(content: HTMLElement, view: ReportView): void {
  const title = view.live ? "Prepare the assessment report" : "Prepare a snapshot summary";
  content.append(
    intro(
      title,
      view.live
        ? "Export the current graph assessment. The report covers the loaded graph, not only the selected application."
        : "Export a local summary of the loaded snapshot. This is distinct from a full Neo4j assessment report.",
      "/* leave a paper trail. */",
    ),
  );
  const left = el("section", { class: "folio-main-column" });
  if (view.selected) left.append(appIdentity(view.selected));
  const output = el("fieldset", { class: "folio-output" }, [el("legend", { text: "Output" })]);
  for (const [format, label] of [
    ["markdown", "Markdown (.md)"],
    ["html", "HTML (.html)"],
  ] as const) {
    const input = el("input", { type: "radio", name: "folio-format", value: format });
    input.checked = view.format === format;
    input.disabled = view.busy;
    input.addEventListener("change", () => {
      view.format = format;
      view.filename =
        view.filename.replace(/\.(md|html)$/, "") + (format === "html" ? ".html" : ".md");
      view.render();
    });
    output.append(
      el("label", { class: "folio-format" }, [
        input,
        el("span", {}, [
          el("strong", { text: label }),
          para(
            format === "html"
              ? "Formatted document for offline review."
              : "Plain text format for local review.",
          ),
        ]),
      ]),
    );
  }
  const filename = el("input", { id: "folio-filename", value: view.filename, maxlength: "180" });
  filename.disabled = view.busy;
  filename.addEventListener("input", () => {
    view.filename = filename.value;
  });
  output.append(
    el("div", { class: "folio-output-fields" }, [
      el("label", { for: "folio-filename", text: "Filename" }),
      filename,
      el("span", { text: "Destination" }),
      para("Chosen by your browser download settings"),
      el("span", { text: "Metadata source" }),
      para(sourceName(view.graph)),
    ]),
  );
  left.append(
    output,
    warning(view.graph),
    para("Report generation does not change host security settings.", "folio-note"),
  );
  content.append(left, reportContext(view));
}
function reportContext(view: ReportView): HTMLElement {
  return el("aside", { class: "folio-aside" }, [
    heading("Included context"),
    el(
      "ul",
      { class: "folio-context" },
      [
        [
          view.live ? "Loaded graph assessment" : "Local snapshot summary",
          view.live
            ? "Assessment findings from the packaged analysis queries."
            : "Recorded applications, modeled FDA relationships, and loaded recommendations.",
        ],
        ["Available source metadata", "Missing collection metadata remains explicitly unknown."],
        ["Recommendations", "Prioritized advice and supporting context; no automatic remediation."],
      ].map(([title, description]) =>
        el("li", {}, [
          el("span", { text: "✓", "aria-hidden": "true" }),
          el("div", {}, [el("h3", { text: title ?? "" }), para(description ?? "")]),
        ]),
      ),
    ),
  ]);
}

export function reportContent(body: unknown): string {
  if (!body || typeof body !== "object") throw new Error("Invalid report response");
  if (!("content" in body) || typeof body.content !== "string")
    throw new Error("Invalid report content");
  if (!("media_type" in body) || typeof body.media_type !== "string")
    throw new Error("Invalid report media type");
  return body.content;
}
export async function prepareReport(
  controller: Controller,
  format: "markdown" | "html",
): Promise<Blob> {
  let content: string;
  if (controller.state.live.enabled) {
    const response = await apiFetch(controller, "/api/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format }),
    });
    content = reportContent(await response.json());
  } else {
    content = snapshotSummary(controller.state.graph);
    if (format === "html") content = snapshotHtml(controller.state.graph);
  }
  const mediaType = format === "html" ? "text/html;charset=utf-8" : "text/markdown;charset=utf-8";
  return new Blob([content], { type: mediaType });
}

export function validFilename(filename: string): boolean {
  return (
    filename.trim().length > 0 &&
    !/[\\/]/.test(filename) &&
    !Array.from(filename).some((character) => character.charCodeAt(0) < 32)
  );
}
