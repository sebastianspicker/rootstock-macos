/** Implements live-viewer requests while keeping API targets and session credentials within the viewer boundary. */

import { element } from "./runtime";
import {
  parseGraphPayload,
  parseOwnedList,
  parseOwnedUpdate,
  parseQueryList,
  parseQueryResult,
  parseTierResponse,
  queryParameterNames,
  resolveSameOriginApiTarget,
  responseErrorDetail,
} from "./protocol";
import { HISTORY_STORAGE_NAME, clearApiToken, getApiToken, readLocal, writeLocal } from "./storage";
import { renderQueryResult } from "./live-queries";
import { markConnected, markConnectionFailed } from "./connection";
import type { Controller } from "./runtime";
import type { NodeId, QueryDescriptor, ViewerNode } from "./types";

const queryGenerations = new WeakMap<Controller, number>();

/** Sends authenticated live requests only through the state-owned same-origin API target. */
export async function apiFetch(
  controller: Controller,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const target = resolveApiTarget(controller.state.live.apiBaseUrl, path);
  const headers = new Headers(init.headers);
  const token = getApiToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetchWithTimeout(target, init, headers);
  return validatedResponse(controller, response);
}

export function resolveApiTarget(
  apiBaseUrl: string,
  path: string,
  origin = window.location.origin,
): string {
  return resolveSameOriginApiTarget(apiBaseUrl, path, origin);
}

export async function fetchWithTimeout(
  target: string,
  init: RequestInit,
  headers: Headers,
): Promise<Response> {
  const timeout = new AbortController();
  const timeoutId = window.setTimeout(() => timeout.abort(), 15_000);
  try {
    return await fetch(target, { ...init, headers, signal: init.signal ?? timeout.signal });
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

export async function validatedResponse(
  controller: Controller,
  response: Response,
): Promise<Response> {
  if (response.status === 401) expireSession(controller);
  if (response.ok) return response;
  throw new Error(await responseFailureDetail(response));
}

export function expireSession(controller: Controller): void {
  clearApiToken();
  controller.actions.showConnectionGate(
    controller,
    "Session expired or token rejected. Enter the current API token.",
  );
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
    markConnected(controller);
    controller.actions.replaceGraph(controller, payload);
    controller.actions.setLiveStatus(controller, "Graph refreshed.", "ok");
  } catch (error) {
    if (generation !== controller.state.live.refreshGeneration) return;
    markConnectionFailed(controller);
    controller.actions.setLiveStatus(
      controller,
      `Graph refresh failed: ${errorMessage(error)}`,
      "error",
    );
  }
}

export function renderQueryFailure(controller: Controller, title: string, error: unknown): void {
  const message = errorMessage(error);
  controller.dom.resultsTitle.textContent = title;
  controller.dom.resultsMeta.textContent = `Error: ${message}`;
  controller.dom.resultsBody.replaceChildren(
    element("div", { class: "empty-state", text: `Query failed: ${message}` }),
  );
  controller.dom.inspector.classList.remove("open");
  controller.dom.resultsPanel.classList.add("open");
  controller.dom.detailEmpty.hidden = true;
}

export async function runQueryRequest(
  controller: Controller,
  title: string,
  path: string,
  init: RequestInit,
): Promise<void> {
  // A slower earlier response must not replace the result of a later request.
  const generation = (queryGenerations.get(controller) ?? 0) + 1;
  queryGenerations.set(controller, generation);
  controller.dom.resultsTitle.textContent = title;
  controller.dom.resultsMeta.textContent = "Running…";
  controller.dom.resultsBody.replaceChildren();
  controller.dom.resultsPanel.classList.add("open");
  controller.dom.detailEmpty.hidden = true;
  try {
    const response = await apiFetch(controller, path, init);
    const result = parseQueryResult(await response.json());
    if (queryGenerations.get(controller) !== generation) return;
    renderQueryResult(controller, title, result);
  } catch (error) {
    if (queryGenerations.get(controller) !== generation) return;
    renderQueryFailure(controller, title, error);
  }
}

export async function runSavedQuery(
  controller: Controller,
  query: QueryDescriptor,
  params: Record<string, unknown> = {},
): Promise<void> {
  await runQueryRequest(
    controller,
    `[${query.id}] ${query.name}`,
    `/api/queries/${encodeURIComponent(query.id)}/run`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ params }),
    },
  );
}

export async function loadLiveQueries(controller: Controller): Promise<void> {
  const { queryList } = controller.dom;
  queryList.replaceChildren(element("p", { class: "empty-state", text: "Loading saved queries…" }));
  try {
    const response = await apiFetch(controller, "/api/queries");
    renderSavedQueries(controller, parseQueryList(await response.json()));
  } catch (error) {
    const message = `Saved queries failed to load: ${errorMessage(error)}`;
    queryList.replaceChildren(element("p", { class: "empty-state", text: message }));
    controller.actions.setLiveStatus(controller, message, "error");
  }
}

export function renderSavedQueries(controller: Controller, queries: QueryDescriptor[]): void {
  const { queryList } = controller.dom;
  queryList.replaceChildren();
  for (const query of queries) queryList.appendChild(queryButton(controller, query));
  if (queries.length === 0)
    queryList.appendChild(
      element("p", { class: "empty-state", text: "No saved queries are available." }),
    );
}

export function queryButton(controller: Controller, query: QueryDescriptor): HTMLElement {
  const item = element("button", { type: "button", class: "query-item", title: query.purpose }, [
    element("span", {
      class: `severity-dot ${query.severity.toLowerCase()}`,
      "aria-hidden": "true",
    }),
    element("span", { class: "query-name", text: `[${query.id}] ${query.name}` }),
    element("span", { class: "cat-badge", text: query.category.split(" ")[0] ?? "Other" }),
  ]);
  const names = queryParameterNames(query.parameters);
  if (names.length === 0) {
    item.addEventListener("click", () => void runSavedQuery(controller, query));
    return item;
  }
  const form = queryParameterForm(controller, query, names);
  item.setAttribute("aria-expanded", "false");
  item.addEventListener("click", () => {
    form.hidden = !form.hidden;
    item.setAttribute("aria-expanded", String(!form.hidden));
    if (!form.hidden) form.querySelector("input")?.focus();
  });
  return element("div", { class: "query-entry" }, [item, form]);
}

/** One labelled input per `$name` token; empty inputs are omitted so the server can apply defaults. */
export function queryParameterForm(
  controller: Controller,
  query: QueryDescriptor,
  names: string[],
): HTMLFormElement {
  const form = element("form", { class: "query-params" });
  form.hidden = true;
  for (const name of names) {
    const id = `query-${query.id}-${name}`.replace(/[^A-Za-z0-9_-]/g, "-");
    form.append(
      element("label", { for: id, text: name.replaceAll("_", " ") }),
      element("input", { id, name, type: "text", autocomplete: "off" }),
    );
  }
  form.append(element("button", { type: "submit", class: "secondary-action", text: "Run" }));
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void runSavedQuery(controller, query, queryParameterValues(form, names));
  });
  return form;
}

/** Packaged queries compare these parameters numerically; every other value stays a string. */
const NUMERIC_PARAMETERS = new Set(["min_permissions", "days_old", "min_methods", "limit"]);

export function queryParameterValues(
  form: HTMLFormElement,
  names: string[],
): Record<string, unknown> {
  const params: Record<string, unknown> = {};
  for (const name of names) {
    const input = form.elements.namedItem(name);
    const text = input instanceof HTMLInputElement ? input.value.trim() : "";
    if (!text) continue;
    params[name] = NUMERIC_PARAMETERS.has(name) && /^-?\d+$/.test(text) ? Number(text) : text;
  }
  return params;
}

export function readHistory(): string[] {
  try {
    const value: unknown = JSON.parse(readLocal(HISTORY_STORAGE_NAME) ?? "[]");
    return Array.isArray(value)
      ? value.filter((item): item is string => typeof item === "string").slice(0, 10)
      : [];
  } catch {
    return [];
  }
}

export function renderHistory(controller: Controller, history: string[]): void {
  while (controller.dom.cypherHistory.options.length > 1) controller.dom.cypherHistory.remove(1);
  for (const query of history)
    controller.dom.cypherHistory.appendChild(
      element("option", {
        value: query,
        text: query.length > 40 ? `${query.slice(0, 40)}…` : query,
      }),
    );
}

export async function runCustomCypher(controller: Controller): Promise<void> {
  const cypher = controller.dom.cypherInput.value.trim();
  if (!cypher) {
    controller.actions.setLiveStatus(
      controller,
      "Enter a read-only Cypher query before running it.",
      "error",
    );
    controller.dom.cypherInput.focus();
    return;
  }
  const history = [cypher, ...readHistory().filter((entry) => entry !== cypher)].slice(0, 10);
  writeLocal(HISTORY_STORAGE_NAME, JSON.stringify(history));
  renderHistory(controller, history);
  controller.dom.runCypher.disabled = true;
  controller.dom.runCypher.textContent = "Running…";
  try {
    await runQueryRequest(controller, "Custom Cypher", "/api/cypher", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cypher, params: {} }),
    });
  } finally {
    controller.dom.runCypher.disabled = false;
    controller.dom.runCypher.textContent = "Run query";
  }
}

export async function liveTierClassify(controller: Controller): Promise<void> {
  controller.actions.setLiveStatus(controller, "Classifying tiers...", "pending");
  try {
    const response = await apiFetch(controller, "/api/tier-classify", { method: "POST" });
    const result = parseTierResponse(await response.json());
    controller.actions.setLiveStatus(
      controller,
      `Tier classification complete: T0=${result.tier0} T1=${result.tier1} T2=${result.tier2}`,
      "ok",
    );
    await liveRefresh(controller);
  } catch (error) {
    controller.actions.setLiveStatus(
      controller,
      `Tier classification failed: ${errorMessage(error)}`,
      "error",
    );
  }
}

export async function liveShowOwned(controller: Controller): Promise<void> {
  controller.actions.setLiveStatus(controller, "Loading owned nodes...", "pending");
  try {
    const response = await apiFetch(controller, "/api/owned");
    const result = parseOwnedList(await response.json());
    const matched = markOwnedNodes(controller, result.owned);
    if (matched > 0) {
      controller.actions.markDirty(controller);
      controller.actions.updateVisibility(controller);
    }
    const message =
      matched === result.count
        ? `${matched} owned node(s) highlighted.`
        : `Owned list loaded, but only ${matched} of ${result.count} matched the current graph.`;
    controller.actions.setLiveStatus(
      controller,
      message,
      matched === result.count ? "ok" : "error",
    );
  } catch (error) {
    controller.actions.setLiveStatus(
      controller,
      `Show owned failed: ${errorMessage(error)}`,
      "error",
    );
  }
}

/** Counts owned entries that matched; every node carrying the name or bundle ID is marked. */
export function markOwnedNodes(controller: Controller, owned: { name: string }[]): number {
  let matched = 0;
  for (const item of owned) {
    const nodes = controller.state.graph.nodes.filter(
      (candidate) =>
        candidate.properties.name === item.name || candidate.properties.bundle_id === item.name,
    );
    for (const node of nodes) node.properties.owned = true;
    if (nodes.length > 0) matched += 1;
  }
  return matched;
}

/** The server marks by identifier, so every installation sharing it changes together. */
function setOwned(controller: Controller, node: ViewerNode, owned: boolean): void {
  const bundleId = node.properties.bundle_id;
  for (const candidate of controller.state.graph.nodes)
    if (
      candidate === node ||
      (typeof bundleId === "string" && candidate.properties.bundle_id === bundleId)
    )
      candidate.properties.owned = owned;
}

export async function toggleOwned(controller: Controller, nodeId: NodeId): Promise<void> {
  const node = controller.state.graph.nodeById.get(nodeId);
  if (!node) return;
  const wasOwned = node.properties.owned === true;
  const request = ownedRequest(node);
  if (!request) {
    controller.actions.setLiveStatus(
      controller,
      "Owned update failed: node has no supported identifier.",
      "error",
    );
    return;
  }
  const action = wasOwned ? "Clear owned" : "Mark owned";
  try {
    const response = await apiFetch(controller, wasOwned ? "/api/clear-owned" : "/api/mark-owned", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    const changed = parseOwnedUpdate(await response.json(), wasOwned ? "cleared" : "marked");
    if (changed <= 0) throw new Error("No matching nodes changed");
    setOwned(controller, node, !wasOwned);
    controller.actions.inspectNode(controller, nodeId);
    controller.actions.setLiveStatus(controller, `${action} complete.`, "ok");
  } catch (error) {
    node.properties.owned = wasOwned;
    controller.actions.setLiveStatus(
      controller,
      `${action} failed: ${errorMessage(error)}`,
      "error",
    );
  }
}

export function ownedRequest(node: ViewerNode): Record<string, string[]> | null {
  if (typeof node.properties.bundle_id === "string")
    return { bundle_ids: [node.properties.bundle_id] };
  if (node.kind === "rs_User" && typeof node.properties.name === "string")
    return { usernames: [node.properties.name] };
  return null;
}

export function startLiveSession(controller: Controller): void {
  controller.actions.hideConnectionGate(controller);
  void loadLiveQueries(controller);
  void liveRefresh(controller);
}
