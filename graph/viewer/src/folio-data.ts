/** Evidence folio selectors operate on the loaded snapshot without inventing collection facts. */
import type { GraphModel, ViewerNode, GraphEdge, QueryResult } from "./types";
import { propertyValue } from "./runtime";
import { shortestPath } from "./model";

export const questions = [
  { id: "01", text: "Which apps with Full Disk Access allow modeled injection?" },
  { id: "02", text: "What is the shortest modeled path to Full Disk Access?" },
  { id: "100", text: "Which recommendations affect the most applications?" },
] as const;
export const value = (input: unknown): string =>
  (typeof input === "string" ? input : propertyValue(input)) || "Unknown";
export const nodeName = (node: ViewerNode): string =>
  value(node.properties.name ?? node.label ?? node.id);
export const relationship = (edge: GraphEdge, name: string): boolean => {
  const normalize = (kind: string): string =>
    kind.replace(/^rs_/, "").replaceAll("_", "").toLowerCase();
  return normalize(edge.kind) === normalize(name);
};
const FDA_SERVICE = "kTCCServiceSystemPolicyAllFiles";
function fdaGrants(graph: GraphModel, id: string, allowed: boolean): GraphEdge[] {
  return (graph.outgoing.get(id) ?? [])
    .map((item) => item.edge)
    .filter(
      (edge) =>
        relationship(edge, "HAS_TCC_GRANT") &&
        edge.properties?.allowed === allowed &&
        graph.nodeById.get(edge.target)?.properties.service === FDA_SERVICE,
    );
}
export function fdaEdges(graph: GraphModel, id: string): GraphEdge[] {
  return fdaGrants(graph, id, true);
}
/** A recorded grant with `allowed: false` is observed evidence, not a missing fact. */
export function deniedFdaEdges(graph: GraphModel, id: string): GraphEdge[] {
  return fdaGrants(graph, id, false);
}
export function edgeKindLabel(kind: string): string {
  return kind.replace(/^rs_/, "").replace(/([a-z])([A-Z])/g, "$1 $2");
}
export function edgeBasis(edge: GraphEdge): "inferred" | "observed" {
  return edge.properties?.inferred === true || edge.properties?._inferred === true
    ? "inferred"
    : "observed";
}
export function injectionEdges(graph: GraphModel, id: string): GraphEdge[] {
  return (graph.incoming.get(id) ?? [])
    .map((item) => item.edge)
    .filter(
      (edge) =>
        relationship(edge, "CAN_INJECT_INTO") &&
        graph.nodeById.get(edge.source)?.properties.bundle_id === "attacker.payload",
    );
}
export function injectableApps(graph: GraphModel): ViewerNode[] {
  return graph.nodes.filter(
    (node) => fdaEdges(graph, node.id).length > 0 && injectionEdges(graph, node.id).length > 0,
  );
}
export function recommendations(graph: GraphModel, id?: string): ViewerNode[] {
  const ids = new Set(
    graph.edges
      .filter((edge) => relationship(edge, "HAS_RECOMMENDATION") && (!id || edge.source === id))
      .map((edge) => edge.target),
  );
  const priorities = ["critical", "high", "medium", "low"];
  return graph.nodes
    .filter((node) => ids.has(node.id))
    .sort((a, b) => {
      if (!id) return affectedApps(graph, b.id) - affectedApps(graph, a.id);
      const rank = (node: ViewerNode): number => {
        const index = priorities.indexOf(value(node.properties.priority).toLowerCase());
        return index < 0 ? 4 : index;
      };
      return rank(a) - rank(b);
    });
}
export function affectedApps(graph: GraphModel, id: string): number {
  return new Set(
    (graph.incoming.get(id) ?? [])
      .map((item) => item.edge)
      .filter((edge) => relationship(edge, "HAS_RECOMMENDATION"))
      .map((edge) => edge.source),
  ).size;
}
/** Graph without denied grants, so path search cannot pass through a refused permission. */
function withoutDeniedGrants(graph: GraphModel): GraphModel {
  const allowed = (edge: GraphEdge): boolean =>
    !(relationship(edge, "HAS_TCC_GRANT") && edge.properties?.allowed === false);
  const outgoing = new Map(
    [...graph.outgoing.entries()].map(([id, entries]) => [
      id,
      entries.filter((entry) => allowed(entry.edge)),
    ]),
  );
  return { ...graph, outgoing };
}
/** Shortest traversable path (as the Paths workspace computes it) from the modeled payload to Full Disk Access. */
export function shortestFdaPath(graph: GraphModel): ViewerNode[] {
  const start = graph.nodes.find((node) => node.properties.bundle_id === "attacker.payload");
  if (!start) return [];
  const searchable = withoutDeniedGrants(graph);
  const best = graph.nodes
    .filter((target) => target.properties.service === FDA_SERVICE)
    .map((target) => shortestPath(searchable, start.id, target.id)?.orderedNodeIds ?? [])
    .filter((path) => path.length > 0)
    .reduce<string[]>(
      (shortest, path) => (shortest.length && shortest.length <= path.length ? shortest : path),
      [],
    );
  return best.flatMap((id) => {
    const node = graph.nodeById.get(id);
    return node ? [node] : [];
  });
}
export function sourceName(graph: GraphModel): string {
  const metadata = graph.payload.metadata ?? {};
  if (metadata.source || metadata.source_kind)
    return value(metadata.source ?? metadata.source_kind);
  return graph.nodes.some((node) => /^(rs_)?Computer$/.test(node.kind))
    ? "Collector scan"
    : "Unknown";
}
export function scopeMetadata(graph: GraphModel): {
  host: string;
  collected: string;
  source: string;
  scope: string;
} {
  const metadata = graph.payload.metadata ?? {};
  const computers = graph.nodes.filter((node) => /^(rs_)?Computer$/.test(node.kind));
  const computer = computers[0]?.properties ?? {};
  const host =
    computers.length > 1
      ? `${computers.length} hosts in loaded graph`
      : value(metadata.hostname ?? computer.hostname);
  const collected =
    computers.length > 1
      ? "Multiple host scans · review Graph tools for timestamps"
      : value(metadata.collected_at ?? computer.scanned_at);
  return {
    host,
    collected,
    source: sourceName(graph),
    scope: `${graph.nodes.length} nodes · ${graph.edges.length} relationships · ${computers.length} recorded host(s)`,
  };
}
function hostCoverage(graph: GraphModel): string[] {
  return graph.nodes
    .filter((node) => /^(rs_)?Computer$/.test(node.kind))
    .flatMap((node) => {
      const p = node.properties;
      const messages: string[] = [];
      if (typeof p.collection_error_count === "number" && p.collection_error_count > 0)
        messages.push(
          `${p.collection_error_count} collection warnings · ${value(p.collection_error_sources)}`,
        );
      if (Number(p.tcc_grants_skipped) > 0)
        messages.push(`${value(p.tcc_grants_skipped)} TCC grants skipped`);
      if (p.import_status === "partial") messages.push("Partial import");
      return messages;
    });
}
export function coverageText(graph: GraphModel): string {
  const metadata = graph.payload.metadata ?? {};
  const errors = metadata.collection_errors ?? metadata.errors;
  if (Array.isArray(errors) && errors.length > 0)
    return `${errors.length} collection warning${errors.length === 1 ? "" : "s"} · ${errors.map(value).join("; ")} · Partial coverage`;
  const hostWarnings = hostCoverage(graph);
  if (hostWarnings.length) return `${hostWarnings.join("; ")} · Partial coverage`;
  if (typeof metadata.coverage === "string") return `Collection coverage: ${metadata.coverage}`;
  return "Collection coverage unknown · Missing evidence is not a negative finding.";
}
export function matchApplication(
  graph: GraphModel,
  row: Record<string, unknown>,
): ViewerNode | undefined {
  // Identity includes the installation path: bundle IDs alone may identify multiple apps.
  if (typeof row.path !== "string" || typeof row.bundle_id !== "string") return undefined;
  return graph.nodes.find(
    (node) => node.properties.path === row.path && node.properties.bundle_id === row.bundle_id,
  );
}
export function snapshotSummary(graph: GraphModel): string {
  return [
    "# Rootstock local snapshot summary",
    "",
    "This is a summary of the loaded viewer snapshot, not a full Neo4j assessment report.",
    "Modeled exposure is not confirmation of compromise. Host settings are unchanged.",
    "",
    `Source: ${sourceName(graph)}`,
    `Host: ${scopeMetadata(graph).host}`,
    `Collected: ${scopeMetadata(graph).collected}`,
    coverageText(graph),
    "",
    `Nodes: ${graph.nodes.length}; relationships: ${graph.edges.length}`,
    "",
    "## Applications with modeled injection and an observed allowed Full Disk Access grant",
    ...injectableApps(graph).map(
      (node) =>
        `- ${nodeName(node)} | ${value(node.properties.bundle_id)} | ${value(node.properties.path)}`,
    ),
    "",
    "## Loaded recommendations",
    ...recommendations(graph).map(
      (node) =>
        `- ${value(node.properties.priority)}: ${value(node.properties.text ?? node.label)} (${affectedApps(graph, node.id)} affected applications)`,
    ),
  ].join("\n");
}

export function localResult(graph: GraphModel, question: string): QueryResult {
  let rows: Record<string, unknown>[];
  if (question === "01")
    rows = injectableApps(graph).map((node) => ({
      app_name: nodeName(node),
      bundle_id: node.properties.bundle_id,
      path: node.properties.path,
    }));
  else if (question === "100")
    rows = recommendations(graph).map((node) => ({
      recommendation: node.properties.text ?? node.label,
      priority: node.properties.priority,
      affected_apps: affectedApps(graph, node.id),
    }));
  else {
    const path = shortestFdaPath(graph);
    rows = path.length
      ? [
          {
            node_names: path.map(nodeName),
            path_length: path.length - 1,
            scope: "One shortest traversable directed path in the loaded snapshot",
          },
        ]
      : [];
  }
  return { rows, columns: Object.keys(rows[0] ?? {}), count: rows.length, truncated: false };
}
