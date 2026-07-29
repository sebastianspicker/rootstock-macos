/** Implements live-viewer requests while keeping API targets and session credentials within the viewer boundary. */

import {element, propertyValue} from "./runtime";
import {
  parseGraphPayload,
  parseOwnedList,
  parseOwnedUpdate,
  parseQueryList,
  parseQueryResult,
  parseTierResponse,
  queryResultMeta,
  resolveSameOriginApiTarget,
  responseErrorDetail,
} from "./protocol";
import {HISTORY_STORAGE_NAME, SESSION_STORAGE_NAME} from "./storage";
import type {Controller} from "./runtime";
import type {NodeId, QueryDescriptor, QueryResult, ViewerNode} from "./types";

/** Sends authenticated live requests only through the state-owned same-origin API target. */
export async function apiFetch(controller: Controller, path: string, init: RequestInit = {}): Promise<Response> {
  const target = resolveApiTarget(controller.state.live.apiBaseUrl, path);
  const headers = new Headers(init.headers);
  const token = sessionStorage.getItem(SESSION_STORAGE_NAME);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetchWithTimeout(target, init, headers);
  return validatedResponse(controller, response);
}

export function resolveApiTarget(apiBaseUrl: string, path: string, origin = window.location.origin): string {
  return resolveSameOriginApiTarget(apiBaseUrl, path, origin);
}

export async function fetchWithTimeout(target: string, init: RequestInit, headers: Headers): Promise<Response> {
  const timeout = new AbortController();
  const timeoutId = window.setTimeout(() => timeout.abort(), 15_000);
  try {
    return await fetch(target, {...init, headers, signal: init.signal ?? timeout.signal});
  } catch (error) {
    throw requestFailure(error);
  } finally {
    window.clearTimeout(timeoutId);
  }
}

export function requestFailure(error: unknown): Error | unknown {
  return error instanceof DOMException && error.name === "AbortError"
    ? new Error("Request timed out after 15 seconds")
    : error;
}

export async function validatedResponse(controller: Controller, response: Response): Promise<Response> {
  if (response.status === 401) expireSession(controller);
  if (response.ok) return response;
  throw new Error(await responseFailureDetail(response));
}

export function expireSession(controller: Controller): void {
  sessionStorage.removeItem(SESSION_STORAGE_NAME);
  controller.actions.showConnectionGate(controller, "Session expired or token rejected. Enter the current API token.");
}

export async function responseFailureDetail(response: Response): Promise<string> {
  const detail = await responseErrorDetail(response);
  const suffix = response.statusText ? ` ${response.statusText}` : "";
  const status = `HTTP ${response.status}${suffix}`;
  return detail ? `${status}: ${detail}` : status;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function liveRefresh(controller: Controller): Promise<void> {
  if (!controller.state.live.enabled) return;
  const generation = ++controller.state.live.refreshGeneration;
  controller.actions.setLiveStatus(controller, "Refreshing graph...", "pending");
  try {
    const response = await apiFetch(controller, "/api/graph");
    const payload = parseGraphPayload(await response.json());
    if (generation !== controller.state.live.refreshGeneration) return;
    controller.actions.replaceGraph(controller, payload);
    controller.actions.setLiveStatus(controller, "Graph refreshed.", "ok");
  } catch (error) {
    if (generation !== controller.state.live.refreshGeneration) return;
    controller.actions.setLiveStatus(controller, `Graph refresh failed: ${errorMessage(error)}`, "error");
  }
}

export function resultNodeId(controller: Controller, row: Record<string, unknown>): NodeId | null {
  for (const value of Object.values(row)) {
    if (typeof value !== "string") continue;
    if (controller.state.graph.nodeById.has(value)) return value;
    const node = controller.state.graph.nodes.find((candidate) => candidate.label === value
      || candidate.properties.name === value || candidate.properties.bundle_id === value);
    if (node) return node.id;
  }
  return null;
}

export function renderQueryResult(controller: Controller, title: string, result: QueryResult): void {
  const {dom} = controller;
  dom.resultsTitle.textContent = title;
  dom.resultsMeta.textContent = queryResultMeta(result);
  dom.resultsBody.replaceChildren();
  dom.inspector.classList.remove("open");
  dom.detailEmpty.hidden = true;
  dom.resultsPanel.classList.add("open");
  if (result.rows.length === 0) {
    dom.resultsBody.appendChild(element("div", {class: "prop-row", text: "No results."}));
    return;
  }
  dom.resultsBody.appendChild(queryTable(controller, title, result));
}

export function queryTable(controller: Controller, title: string, result: QueryResult): HTMLTableElement {
  const table = element("table");
  table.append(element("caption", {class: "sr-only", text: `${title} results`}), queryHead(result.columns), queryBody(controller, result));
  return table;
}

export function queryHead(columns: string[]): HTMLTableSectionElement {
  const row = element("tr");
  for (const header of columns) row.appendChild(element("th", {scope: "col", text: header}));
  row.appendChild(element("th", {scope: "col", text: "Action"}));
  return element("thead", {}, [row]);
}

export function queryBody(controller: Controller, result: QueryResult): HTMLTableSectionElement {
  const body = element("tbody");
  for (const row of result.rows) body.appendChild(queryRow(controller, result.columns, row));
  return body;
}

export function queryRow(controller: Controller, columns: string[], row: Record<string, unknown>): HTMLTableRowElement {
  const tableRow = element("tr");
  for (const header of columns) {
    const value = propertyValue(row[header]);
    tableRow.appendChild(element("td", {title: value, text: value}));
  }
  const nodeId = resultNodeId(controller, row);
  const action = element("button", {type: "button", text: "Highlight node"});
  action.disabled = nodeId === null;
  action.addEventListener("click", () => highlightResult(controller, nodeId));
  tableRow.appendChild(element("td", {}, [action]));
  return tableRow;
}

export function highlightResult(controller: Controller, nodeId: NodeId | null): void {
  if (!nodeId) return;
  controller.actions.selectTab(controller, "explore");
  controller.actions.inspectNode(controller, nodeId);
}

export function renderQueryFailure(controller: Controller, title: string, error: unknown): void {
  const message = errorMessage(error);
  controller.dom.resultsTitle.textContent = title;
  controller.dom.resultsMeta.textContent = `Error: ${message}`;
  controller.dom.resultsBody.replaceChildren(element("div", {class: "empty-state", text: `Query failed: ${message}`}));
  controller.dom.inspector.classList.remove("open");
  controller.dom.resultsPanel.classList.add("open");
  controller.dom.detailEmpty.hidden = true;
}

export async function runQueryRequest(controller: Controller, title: string, path: string, init: RequestInit): Promise<void> {
  controller.dom.resultsTitle.textContent = title;
  controller.dom.resultsMeta.textContent = "Running…";
  controller.dom.resultsBody.replaceChildren();
  controller.dom.resultsPanel.classList.add("open");
  controller.dom.detailEmpty.hidden = true;
  try {
    const response = await apiFetch(controller, path, init);
    renderQueryResult(controller, title, parseQueryResult(await response.json()));
  } catch (error) {
    renderQueryFailure(controller, title, error);
  }
}

export async function runSavedQuery(controller: Controller, query: QueryDescriptor): Promise<void> {
  await runQueryRequest(controller, `[${query.id}] ${query.name}`, `/api/queries/${encodeURIComponent(query.id)}/run`, {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({params: {}}),
  });
}

export async function loadLiveQueries(controller: Controller): Promise<void> {
  const {queryList} = controller.dom;
  queryList.replaceChildren(element("p", {class: "empty-state", text: "Loading saved queries…"}));
  try {
    const response = await apiFetch(controller, "/api/queries");
    renderSavedQueries(controller, parseQueryList(await response.json()));
  } catch (error) {
    const message = `Saved queries failed to load: ${errorMessage(error)}`;
    queryList.replaceChildren(element("p", {class: "empty-state", text: message}));
    controller.actions.setLiveStatus(controller, message, "error");
  }
}

export function renderSavedQueries(controller: Controller, queries: QueryDescriptor[]): void {
  const {queryList} = controller.dom;
  queryList.replaceChildren();
  for (const query of queries) queryList.appendChild(queryButton(controller, query));
  if (queries.length === 0) queryList.appendChild(element("p", {class: "empty-state", text: "No saved queries are available."}));
}

export function queryButton(controller: Controller, query: QueryDescriptor): HTMLButtonElement {
  const item = element("button", {type: "button", class: "query-item", title: query.purpose}, [
    element("span", {class: `severity-dot ${query.severity.toLowerCase()}`, "aria-hidden": "true"}),
    element("span", {class: "query-name", text: `[${query.id}] ${query.name}`}),
    element("span", {class: "cat-badge", text: query.category.split(" ")[0] ?? "Other"}),
  ]);
  item.addEventListener("click", () => void runSavedQuery(controller, query));
  return item;
}

export function readHistory(): string[] {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(HISTORY_STORAGE_NAME) ?? "[]");
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string").slice(0, 10) : [];
  } catch { return []; }
}

export function renderHistory(controller: Controller, history: string[]): void {
  while (controller.dom.cypherHistory.options.length > 1) controller.dom.cypherHistory.remove(1);
  for (const query of history) controller.dom.cypherHistory.appendChild(element("option", {
    value: query, text: query.length > 40 ? `${query.slice(0, 40)}…` : query,
  }));
}

export async function runCustomCypher(controller: Controller): Promise<void> {
  const cypher = controller.dom.cypherInput.value.trim();
  if (!cypher) {
    controller.actions.setLiveStatus(controller, "Enter a read-only Cypher query before running it.", "error");
    controller.dom.cypherInput.focus();
    return;
  }
  const history = [cypher, ...readHistory().filter((entry) => entry !== cypher)].slice(0, 10);
  localStorage.setItem(HISTORY_STORAGE_NAME, JSON.stringify(history));
  renderHistory(controller, history);
  controller.dom.runCypher.disabled = true;
  controller.dom.runCypher.textContent = "Running…";
  try {
    await runQueryRequest(controller, "Custom Cypher", "/api/cypher", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({cypher, params: {}})});
  } finally {
    controller.dom.runCypher.disabled = false;
    controller.dom.runCypher.textContent = "Run query";
  }
}

export async function liveTierClassify(controller: Controller): Promise<void> {
  controller.actions.setLiveStatus(controller, "Classifying tiers...", "pending");
  try {
    const response = await apiFetch(controller, "/api/tier-classify", {method: "POST"});
    const result = parseTierResponse(await response.json());
    controller.actions.setLiveStatus(controller, `Tier classification complete: T0=${result.tier0} T1=${result.tier1} T2=${result.tier2}`, "ok");
    await liveRefresh(controller);
  } catch (error) { controller.actions.setLiveStatus(controller, `Tier classification failed: ${errorMessage(error)}`, "error"); }
}

export async function liveShowOwned(controller: Controller): Promise<void> {
  controller.actions.setLiveStatus(controller, "Loading owned nodes...", "pending");
  try {
    const response = await apiFetch(controller, "/api/owned");
    const result = parseOwnedList(await response.json());
    const matched = markOwnedNodes(controller, result.owned);
    if (matched > 0) controller.actions.markDirty(controller);
    const message = matched === result.count ? `${matched} owned node(s) highlighted.` : `Owned list loaded, but only ${matched} of ${result.count} matched the current graph.`;
    controller.actions.setLiveStatus(controller, message, matched === result.count ? "ok" : "error");
  } catch (error) { controller.actions.setLiveStatus(controller, `Show owned failed: ${errorMessage(error)}`, "error"); }
}

export function markOwnedNodes(controller: Controller, owned: {name: string}[]): number {
  let matched = 0;
  for (const item of owned) {
    const node = controller.state.graph.nodes.find((candidate) => candidate.properties.name === item.name || candidate.properties.bundle_id === item.name);
    if (!node) continue;
    node.properties.owned = true;
    matched += 1;
  }
  return matched;
}

export async function toggleOwned(controller: Controller, nodeId: NodeId): Promise<void> {
  const node = controller.state.graph.nodeById.get(nodeId);
  if (!node) return;
  const wasOwned = node.properties.owned === true;
  const request = ownedRequest(node);
  if (!request) { controller.actions.setLiveStatus(controller, "Owned update failed: node has no supported identifier.", "error"); return; }
  const action = wasOwned ? "Clear owned" : "Mark owned";
  try {
    const response = await apiFetch(controller, wasOwned ? "/api/clear-owned" : "/api/mark-owned", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(request)});
    const changed = parseOwnedUpdate(await response.json(), wasOwned ? "cleared" : "marked");
    if (changed <= 0) throw new Error("No matching nodes changed");
    node.properties.owned = !wasOwned;
    controller.actions.inspectNode(controller, nodeId);
    controller.actions.setLiveStatus(controller, `${action} complete.`, "ok");
  } catch (error) {
    node.properties.owned = wasOwned;
    controller.actions.setLiveStatus(controller, `${action} failed: ${errorMessage(error)}`, "error");
  }
}

export function ownedRequest(node: ViewerNode): Record<string, string[]> | null {
  if (typeof node.properties.bundle_id === "string") return {bundle_ids: [node.properties.bundle_id]};
  if (node.kind === "rs_User" && typeof node.properties.name === "string") return {usernames: [node.properties.name]};
  return null;
}

export function startLiveSession(controller: Controller): void {
  controller.actions.hideConnectionGate(controller);
  void loadLiveQueries(controller);
  void liveRefresh(controller);
}
