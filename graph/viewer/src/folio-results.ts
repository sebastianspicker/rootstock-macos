/** Searchable semantic query results with installation-specific evidence selection. */
import type { GraphModel, QueryResult, ViewerNode } from "./types";
import { value, matchApplication } from "./folio-data";
import { resultNode } from "./folio-host-answers";
import { el, para, button } from "./folio-ui";
interface ResultsView {
  graph: GraphModel;
  live: boolean;
  result: QueryResult | undefined;
  select(node: ViewerNode | undefined): void;
  /** Opens a non-application row's node in Graph tools. */
  inspect(node: ViewerNode): void;
}
export function renderResults(parent: HTMLElement, view: ResultsView): void {
  const rows = view.result?.rows ?? [];
  parent.append(
    para(
      `${rows.length} returned ${rows.length === 1 ? "row" : "rows"} · ${view.live ? "Read-only query" : "Loaded snapshot inspection"}`,
      "folio-code",
    ),
  );
  if (!rows.length) {
    parent.append(
      para(
        "No matches found in the loaded evidence. Collection gaps remain relevant; this does not establish that the host is safe.",
        "folio-empty",
      ),
    );
    return;
  }
  const table = el("table", { class: "folio-table" });
  const columns = view.result?.columns ?? [];
  table.append(
    el("caption", { text: "Analysis results" }),
    el("thead", {}, [
      el("tr", {}, [
        ...columns.map((text) => el("th", { scope: "col", text: text.replaceAll("_", " ") })),
        el("th", { scope: "col", text: "Inspect" }),
      ]),
    ]),
  );
  const body = el("tbody");
  const search = el("input", {
    type: "search",
    id: "folio-result-search",
    placeholder: "Filter results by name, identifier, or path",
  });
  const render = (): void => {
    const filtered = rows.filter((row) =>
      Object.values(row).map(value).join(" ").toLowerCase().includes(search.value.toLowerCase()),
    );
    body.replaceChildren(
      ...filtered.map((row) => {
        const cell = el("td", {}, [inspectControl(view, row)]);
        return el("tr", {}, [
          ...columns.map((column) => el("td", { text: value(row[column]) })),
          cell,
        ]);
      }),
    );
    if (!filtered.length)
      body.append(
        el("tr", {}, [
          el("td", {
            colspan: String(columns.length + 1),
            text: "No results match this filter.",
          }),
        ]),
      );
  };
  search.addEventListener("input", render);
  render();
  table.append(body);
  parent.append(
    el("label", { for: "folio-result-search", text: "Search results" }),
    search,
    el("div", { class: "folio-table-scroll" }, [table]),
  );
}

/** App rows open the evidence view; other rows open their node in Graph tools when it is unique. */
function inspectControl(view: ResultsView, row: Record<string, unknown>): HTMLElement {
  const app = matchApplication(view.graph, row);
  if (app) return button("Inspect evidence", () => view.select(app));
  const node = resultNode(view.graph, row);
  if (node) return button("Open in Graph tools", () => view.inspect(node));
  const inspect = button("Inspect evidence", () => {});
  inspect.disabled = true;
  // The reason a row cannot be inspected is visible text, not only a tooltip.
  return el("div", {}, [
    inspect,
    para(
      "No unique node in the loaded snapshot for this row. Use Graph tools for query and path details.",
      "field-help",
    ),
  ]);
}
