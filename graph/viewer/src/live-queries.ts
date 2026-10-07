/** Renders saved-query result tables and the node-highlight action for live sessions. */

import { element, propertyValue } from "./runtime";
import { queryResultMeta } from "./protocol";
import type { Controller } from "./runtime";
import type { NodeId, QueryResult } from "./types";

function resultNodeId(controller: Controller, row: Record<string, unknown>): NodeId | null {
  for (const value of Object.values(row)) {
    if (typeof value !== "string") continue;
    if (controller.state.graph.nodeById.has(value)) return value;
    const node = controller.state.graph.nodes.find(
      (candidate) =>
        candidate.label === value ||
        candidate.properties.name === value ||
        candidate.properties.bundle_id === value,
    );
    if (node) return node.id;
  }
  return null;
}

export function renderQueryResult(
  controller: Controller,
  title: string,
  result: QueryResult,
): void {
  const { dom } = controller;
  dom.resultsTitle.textContent = title;
  dom.resultsMeta.textContent = queryResultMeta(result);
  dom.resultsBody.replaceChildren();
  dom.inspector.classList.remove("open");
  dom.detailEmpty.hidden = true;
  dom.resultsPanel.classList.add("open");
  if (result.rows.length === 0) {
    dom.resultsBody.appendChild(element("div", { class: "prop-row", text: "No results." }));
    return;
  }
  dom.resultsBody.appendChild(queryTable(controller, title, result));
}

function queryTable(controller: Controller, title: string, result: QueryResult): HTMLTableElement {
  const table = element("table");
  table.append(
    element("caption", { class: "sr-only", text: `${title} results` }),
    queryHead(result.columns),
    queryBody(controller, result),
  );
  return table;
}

function queryHead(columns: string[]): HTMLTableSectionElement {
  const row = element("tr");
  for (const header of columns) row.appendChild(element("th", { scope: "col", text: header }));
  row.appendChild(element("th", { scope: "col", text: "Action" }));
  return element("thead", {}, [row]);
}

function queryBody(controller: Controller, result: QueryResult): HTMLTableSectionElement {
  const body = element("tbody");
  for (const row of result.rows) body.appendChild(queryRow(controller, result.columns, row));
  return body;
}

function queryRow(
  controller: Controller,
  columns: string[],
  row: Record<string, unknown>,
): HTMLTableRowElement {
  const tableRow = element("tr");
  for (const header of columns) {
    const value = propertyValue(row[header]);
    tableRow.appendChild(element("td", { title: value, text: value }));
  }
  const nodeId = resultNodeId(controller, row);
  const action = element("button", { type: "button", text: "Highlight node" });
  action.disabled = nodeId === null;
  action.addEventListener("click", () => highlightResult(controller, nodeId));
  tableRow.appendChild(element("td", {}, [action]));
  return tableRow;
}

function highlightResult(controller: Controller, nodeId: NodeId | null): void {
  if (!nodeId) return;
  controller.actions.transitionWorkspace(controller, "graph", true);
  controller.actions.inspectNode(controller, nodeId);
}
