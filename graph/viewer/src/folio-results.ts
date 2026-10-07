/** Searchable semantic query results with installation-specific evidence selection. */
import type { GraphModel, QueryResult, ViewerNode } from "./types";
import { value, matchApplication } from "./folio-data";
import { el, para, button } from "./folio-ui";
interface ResultsView {
  graph: GraphModel;
  live: boolean;
  result: QueryResult | undefined;
  select(node: ViewerNode | undefined): void;
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
        const node = matchApplication(view.graph, row);
        const inspect = button("Inspect evidence", () => {
          view.select(node);
        });
        inspect.disabled = !node;
        const cell = el("td", {}, [inspect]);
        // The reason a row cannot be inspected is visible text, not only a tooltip.
        if (!node)
          cell.append(
            para(
              "No unique application installation in the loaded snapshot for this row. Use Graph tools for query and path details.",
              "field-help",
            ),
          );
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
