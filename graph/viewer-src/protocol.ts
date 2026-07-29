/** Validates untrusted live API payloads before they enter the viewer model. */

import type {
  GraphEdge,
  GraphNodeInput,
  GraphPayload,
  OwnedListResponse,
  QueryDescriptor,
  QueryResult,
  TierResponse,
} from "./types";

/** Hard caps bound client-side graph parsing and rendering work for a single response. */
export const MAX_GRAPH_NODES = 10_000;
export const MAX_GRAPH_EDGES = 50_000;

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isNode(value: unknown): value is GraphNodeInput {
  return isRecord(value) && typeof value.id === "string" && typeof value.kind === "string";
}

export function isEdge(value: unknown): value is GraphEdge {
  return isRecord(value)
    && typeof value.source === "string"
    && typeof value.target === "string"
    && typeof value.kind === "string";
}

/** Accepts only structurally valid graph payloads within the graph-size caps. */
export function parseGraphPayload(value: unknown): GraphPayload {
  if (!isRecord(value) || !isRecord(value.graph)
      || !Array.isArray(value.graph.nodes)
      || value.graph.nodes.length > MAX_GRAPH_NODES
      || !value.graph.nodes.every(isNode)
      || !Array.isArray(value.graph.edges)
      || value.graph.edges.length > MAX_GRAPH_EDGES
      || !value.graph.edges.every(isEdge)) {
    throw new TypeError("Malformed graph response");
  }
  return {
    metadata: isRecord(value.metadata) ? value.metadata : {},
    graph: {nodes: value.graph.nodes, edges: value.graph.edges},
  };
}

/** Validates query descriptors while supplying safe display defaults for optional metadata. */
export function parseQueryList(value: unknown): QueryDescriptor[] {
  if (!Array.isArray(value)) throw new TypeError("Malformed query-list response");
  return value.map((item) => {
    if (!isRecord(item) || typeof item.id !== "string" || typeof item.name !== "string") {
      throw new TypeError("Malformed query-list response");
    }
    return {
      id: item.id,
      name: item.name,
      purpose: typeof item.purpose === "string" ? item.purpose : item.name,
      category: typeof item.category === "string" ? item.category : "Other",
      severity: typeof item.severity === "string" ? item.severity : "Informational",
    };
  });
}

/** Validates query rows and requires any declared result count to match the received rows. */
export function parseQueryResult(value: unknown): QueryResult {
  if (!isRecord(value)) throw new TypeError("Malformed query response");
  const rows = queryRows(value.rows);
  const count = queryCount(value.count, rows.length);
  const columns = queryColumns(value.columns, rows);
  return {rows, columns, count, truncated: value.truncated === true};
}

export function queryResultMeta(result: QueryResult): string {
  return result.truncated
    ? `Showing first ${pluralRows(result.rows.length)} (truncated)`
    : pluralRows(result.rows.length);
}

export function pluralRows(count: number): string { return `${count} ${count === 1 ? "row" : "rows"}`; }

/** Resolves a live API path while rejecting bases and targets outside the viewer origin. */
export function resolveSameOriginApiTarget(apiBaseUrl: string, path: string, origin: string): string {
  const base = new URL(apiBaseUrl || "/", origin);
  const target = new URL(path, base);
  if (base.origin !== origin || target.origin !== origin) throw new Error("Live API target must use the viewer origin");
  return target.toString();
}

export function queryRows(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value) || !value.every(isRecord)) throw new TypeError("Malformed query response");
  return value;
}

export function queryCount(value: unknown, fallback: number): number {
  const count = typeof value === "number" ? value : fallback;
  if (!Number.isInteger(count) || count < 0 || count !== fallback) throw new TypeError("Malformed query response");
  return count;
}

export function queryColumns(value: unknown, rows: Record<string, unknown>[]): string[] {
  return Array.isArray(value) && value.every((column) => typeof column === "string")
    ? value
    : Object.keys(rows[0] ?? {});
}

/** Accepts tier totals only when their reported aggregate is internally consistent. */
export function parseTierResponse(value: unknown): TierResponse {
  if (!isRecord(value)) throw new TypeError("Malformed tier response");
  const fields = ["tier0", "tier1", "tier2", "total"] as const;
  if (fields.some((field) => typeof value[field] !== "number")) {
    throw new TypeError("Malformed tier response");
  }
  const response = {
    tier0: value.tier0 as number,
    tier1: value.tier1 as number,
    tier2: value.tier2 as number,
    total: value.total as number,
  };
  if (response.total !== response.tier0 + response.tier1 + response.tier2) {
    throw new TypeError("Malformed tier response");
  }
  return response;
}

/** Validates ownership entries and requires the server count to match their list length. */
export function parseOwnedList(value: unknown): OwnedListResponse {
  if (!isRecord(value) || !Array.isArray(value.owned)
      || !value.owned.every((item) => isRecord(item) && typeof item.name === "string")
      || typeof value.count !== "number" || value.count !== value.owned.length) {
    throw new TypeError("Malformed owned response");
  }
  return {owned: value.owned as OwnedListResponse["owned"], count: value.count};
}

/** Extracts the requested ownership mutation count from a structurally valid response. */
export function parseOwnedUpdate(value: unknown, key: "marked" | "cleared"): number {
  if (!isRecord(value) || typeof value[key] !== "number") {
    throw new TypeError("Malformed owned update response");
  }
  return value[key];
}

export async function responseErrorDetail(response: Response): Promise<string> {
  const text = await response.text();
  if (!text) return "";
  try {
    const payload: unknown = JSON.parse(text);
    if (isRecord(payload) && typeof payload.detail === "string") return payload.detail;
  } catch {
    return text;
  }
  return text;
}
