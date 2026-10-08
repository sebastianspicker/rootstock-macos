/**
 * Offline answers for the host-evidence questions. Each selector reads only nodes, edges and
 * properties in the loaded snapshot and returns rows shaped like the packaged query of the same
 * id, so live and offline results render alike. `_node_id` links a row to its node and is not a
 * column.
 */
import type { GraphEdge, GraphModel, ViewerNode } from "./types";

export type Row = Record<string, unknown>;

const normalize = (kind: string): string =>
  kind.replace(/^rs_/, "").replaceAll("_", "").toLowerCase();
export const isKind = (node: ViewerNode | undefined, kind: string): node is ViewerNode =>
  node !== undefined && normalize(node.kind) === normalize(kind);
export const ofKind = (graph: GraphModel, kind: string): ViewerNode[] =>
  graph.nodes.filter((node) => isKind(node, kind));
const isEdge = (edge: GraphEdge, kind: string): boolean => normalize(edge.kind) === normalize(kind);
export const text = (input: unknown): string => (typeof input === "string" ? input : "");
export const num = (input: unknown): number =>
  typeof input === "number" && Number.isFinite(input) ? input : 0;
export const strings = (input: unknown): string[] =>
  Array.isArray(input) ? input.filter((item): item is string => typeof item === "string") : [];

/** Nodes of `kind` on the other end of `edgeKind`, in either direction. */
export function linked(
  graph: GraphModel,
  node: ViewerNode,
  edgeKind: string,
  kind: string,
  incoming: boolean,
): ViewerNode[] {
  const entries = incoming
    ? (graph.incoming.get(node.id) ?? []).map((entry) => ({ edge: entry.edge, id: entry.source }))
    : (graph.outgoing.get(node.id) ?? []).map((entry) => ({ edge: entry.edge, id: entry.target }));
  return entries
    .filter((entry) => isEdge(entry.edge, edgeKind))
    .map((entry) => graph.nodeById.get(entry.id))
    .filter((other): other is ViewerNode => isKind(other, kind));
}

export const names = (nodes: ViewerNode[]): string[] => [
  ...new Set(nodes.map((node) => text(node.properties.name) || (node.label ?? node.id))),
];

/** The query joins a Computer on the same scan_id; no scan_id means no recorded host. */
export function hostname(graph: GraphModel, node: ViewerNode): unknown {
  const scan = node.properties.scan_id;
  if (scan === undefined || scan === null) return null;
  return ofKind(graph, "Computer").find((host) => host.properties.scan_id === scan)?.properties
    .hostname;
}

/** Cypher orders strings by code point, so `Z` sorts before `a` here too. */
export function codePointOrder(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function byKeys(...keys: ((row: Row) => number | string)[]): (a: Row, b: Row) => number {
  return (a, b) => {
    for (const key of keys) {
      const left = key(a);
      const right = key(b);
      const order =
        typeof left === "number" && typeof right === "number"
          ? left - right
          : codePointOrder(String(left), String(right));
      if (order !== 0) return order;
    }
    return 0;
  };
}

export const flag = (input: unknown): number => (input === true ? 0 : 1);

function listenerRow(graph: GraphModel, node: ViewerNode): Row {
  const p = node.properties;
  const process = linked(graph, node, "LISTENS_ON", "Process", true)[0];
  return {
    hostname: hostname(graph, node),
    protocol: p.protocol,
    address: p.address,
    port: p.port,
    state: p.state,
    exposed: p.exposed,
    firewall_enabled: p.firewall_enabled,
    reachable_without_firewall: p.reachable_without_firewall === true,
    pid: p.pid,
    process: process?.properties.command ?? p.process_name,
    user: p.user,
    applications: names(linked(graph, node, "LISTENS_ON", "Application", true)),
    bundle_id: p.bundle_id,
    _node_id: node.id,
  };
}

/** Q106: every listener, reachable-without-firewall and exposed ones first. */
export function networkListeners(graph: GraphModel): Row[] {
  return ofKind(graph, "NetworkListener")
    .map((node) => listenerRow(graph, node))
    .sort(
      byKeys(
        (row) => flag(row.reachable_without_firewall),
        (row) => flag(row.exposed),
        (row) => num(row.port),
        (row) => text(row.protocol),
        (row) => num(row.pid),
      ),
    );
}

/** Authorities whose ISSUED_BY chain reaches `root` within four hops, including `root`. */
function chainedAuthorities(graph: GraphModel, root: ViewerNode): ViewerNode[] {
  const seen = new Map([[root.id, root]]);
  let frontier = [root];
  for (let depth = 0; depth < 4 && frontier.length; depth += 1) {
    frontier = frontier
      .flatMap((ca) => linked(graph, ca, "ISSUED_BY", "CertAuthority", true))
      .filter((ca) => !seen.has(ca.id));
    for (const ca of frontier) seen.set(ca.id, ca);
  }
  return [...seen.values()];
}

function signedUnder(graph: GraphModel, certificate: ViewerNode): string[] {
  const authorities = linked(graph, certificate, "SAME_CERTIFICATE", "CertAuthority", false);
  const apps = authorities
    .flatMap((ca) => chainedAuthorities(graph, ca))
    .flatMap((ca) => linked(graph, ca, "SIGNED_BY_CA", "Application", true));
  return names(apps);
}

/** Q107: certificates the Mac trusts through user or admin trust settings. */
export function trustedCertificates(graph: GraphModel): Row[] {
  return ofKind(graph, "Computer")
    .flatMap((host) =>
      linked(graph, host, "TRUSTS_CERTIFICATE", "TrustedCertificate", false).map((node) => {
        const p = node.properties;
        return {
          hostname: host.properties.hostname,
          subject: p.subject,
          issuer: p.issuer,
          domain: p.domain,
          trust_result: p.trust_result,
          custom_root: p.custom_root,
          is_self_signed: p.is_self_signed,
          not_after: p.not_after,
          sha256: p.sha256,
          apps_signed_under_it: signedUnder(graph, node),
          _node_id: node.id,
        };
      }),
    )
    .sort(
      byKeys(
        (row) => flag(row.custom_root),
        (row) => text(row.domain),
        (row) => text(row.subject),
      ),
    );
}

const OUTSIDE_STORE = new Set(["unpacked", "external"]);

/** Q108: extensions with access to every site, or loaded unpacked or side-loaded. */
export function riskyExtensions(graph: GraphModel): Row[] {
  return ofKind(graph, "BrowserExtension")
    .filter(
      (node) =>
        node.properties.broad_host_access === true ||
        OUTSIDE_STORE.has(text(node.properties.install_location)),
    )
    .map((node) => {
      const p = node.properties;
      return {
        hostname: hostname(graph, node),
        browser: p.browser,
        profile: p.profile,
        extension_name: p.name,
        extension_id: p.extension_id,
        version: p.version,
        install_location: p.install_location,
        from_webstore: p.from_webstore,
        enabled: p.enabled,
        broad_host_access: p.broad_host_access,
        sensitive_permissions: strings(p.sensitive_permissions),
        host_permissions: strings(p.host_permissions).slice(0, 5),
        install_time: p.install_time,
        path: p.path,
        _node_id: node.id,
      };
    })
    .sort(
      byKeys(
        (row) => (OUTSIDE_STORE.has(text(row.install_location)) ? 0 : 1),
        (row) => -strings(row.sensitive_permissions).length,
        (row) => text(row.browser),
        (row) => text(row.extension_name),
      ),
    );
}

function launchItemBase(node: ViewerNode): Row {
  return {
    label: node.properties.label,
    type: node.properties.type,
    plist_path: node.properties.path,
  };
}

function runsAs(graph: GraphModel, node: ViewerNode): unknown {
  const user = linked(graph, node, "RUNS_AS", "User", false)[0];
  if (user) return user.properties.name ?? user.label;
  return node.properties.type === "daemon" ? "root" : null;
}

const persistingApps = (graph: GraphModel, node: ViewerNode): string[] =>
  names(linked(graph, node, "PERSISTS_VIA", "Application", true));

const rootFirst = byKeys(
  (row) => (row.runs_as === "root" ? 0 : 1),
  (row) => text(row.type),
  (row) => text(row.label),
);

/** Q109: launch items whose plist sets DYLD_* variables. */
export function launchdInjection(graph: GraphModel): Row[] {
  return ofKind(graph, "LaunchItem")
    .filter((node) => strings(node.properties.dyld_environment).length > 0)
    .map((node) => ({
      ...launchItemBase(node),
      program: node.properties.program,
      dyld_environment: strings(node.properties.dyld_environment),
      environment_variable_names: node.properties.environment_variable_names,
      runs_as: runsAs(graph, node),
      loaded: node.properties.loaded,
      run_at_load: node.properties.run_at_load,
      plist_writable_by_non_root: node.properties.plist_writable_by_non_root,
      applications: persistingApps(graph, node),
      _node_id: node.id,
    }))
    .sort(rootFirst);
}

/** Q110: launch items whose program no longer exists on disk. */
export function stalePersistence(graph: GraphModel): Row[] {
  return ofKind(graph, "LaunchItem")
    .filter((node) => node.properties.program_exists === false)
    .map((node) => ({
      ...launchItemBase(node),
      missing_program: node.properties.program,
      loaded: node.properties.loaded,
      disabled: node.properties.disabled,
      run_at_load: node.properties.run_at_load,
      plist_modified: node.properties.plist_modified,
      applications: persistingApps(graph, node),
      _node_id: node.id,
    }))
    .sort(
      byKeys(
        (row) => (row.type === "daemon" ? 0 : 1),
        (row) => text(row.label),
      ),
    );
}

const WRITABLE_FLAGS = [
  "program_in_user_writable_location",
  "program_writable_by_non_root",
  "plist_writable_by_non_root",
] as const;

/** Q111: launch items an ordinary user can redirect through the program or the plist. */
export function userWritablePersistence(graph: GraphModel): Row[] {
  return ofKind(graph, "LaunchItem")
    .filter((node) => WRITABLE_FLAGS.some((key) => node.properties[key] === true))
    .map((node) => ({
      ...launchItemBase(node),
      program: node.properties.program,
      ...Object.fromEntries(WRITABLE_FLAGS.map((key) => [key, node.properties[key]])),
      program_owner: node.properties.program_owner,
      runs_as: runsAs(graph, node),
      applications: persistingApps(graph, node),
      _node_id: node.id,
    }))
    .sort(rootFirst);
}
