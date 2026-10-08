/** Offline answers for installed-software CVEs and host settings, plus the host question dispatch. */
import type { GraphModel, ViewerNode } from "./types";
import {
  byKeys,
  codePointOrder,
  isKind,
  launchdInjection,
  networkListeners,
  num,
  ofKind,
  riskyExtensions,
  stalePersistence,
  text,
  trustedCertificates,
  userWritablePersistence,
} from "./folio-host-questions";
import type { Row } from "./folio-host-questions";

function nvdMatches(graph: GraphModel, app: ViewerNode): { cpe: unknown; cve: ViewerNode }[] {
  return (graph.outgoing.get(app.id) ?? [])
    .filter(
      (entry) =>
        /^(rs_)?AffectedBy$/i.test(entry.edge.kind) && entry.edge.properties?.match_tier === "cpe",
    )
    .map((entry) => ({ cpe: entry.edge.properties?.cpe, cve: graph.nodeById.get(entry.target) }))
    .filter((match): match is { cpe: unknown; cve: ViewerNode } =>
      isKind(match.cve, "Vulnerability"),
    );
}

/** KEV first, then highest CVSS, then most recently published (as query 104 orders them). */
function cveOrder(left: Row, right: Row): number {
  const kev = Number(right.in_kev === true) - Number(left.in_kev === true);
  const cvss = num(right.cvss_score) - num(left.cvss_score);
  return kev || cvss || codePointOrder(text(right.published), text(left.published));
}

function installedRow(app: ViewerNode, matches: { cpe: unknown; cve: ViewerNode }[]): Row {
  const cves = [...new Map(matches.map((match) => [match.cve.id, match.cve])).values()]
    .map((cve) => cve.properties)
    .sort(cveOrder);
  return {
    app_name: app.properties.name ?? app.label,
    bundle_id: app.properties.bundle_id,
    app_version: app.properties.version,
    cpe: [...new Set(matches.map((match) => text(match.cpe)).filter(Boolean))],
    cve_count: cves.length,
    kev_count: cves.filter((cve) => cve.in_kev === true).length,
    max_cvss: cves.reduce((best, cve) => Math.max(best, num(cve.cvss_score)), 0),
    top_cves: cves.slice(0, 5).map((cve) => cve.cve_id),
    _node_id: app.id,
  };
}

/** Q104: per application, the NVD CVEs matched to its exact version (AFFECTED_BY match_tier cpe). */
export function installedSoftwareCves(graph: GraphModel): Row[] {
  return ofKind(graph, "Application")
    .map((app) => ({ app, matches: nvdMatches(graph, app) }))
    .filter((entry) => entry.matches.length > 0)
    .map((entry) => installedRow(entry.app, entry.matches))
    .sort(
      byKeys(
        (row) => -num(row.kev_count),
        (row) => -num(row.max_cvss),
        (row) => -num(row.cve_count),
        (row) => text(row.app_name),
      ),
    );
}

function subjectName(node: ViewerNode | undefined): unknown {
  return node?.properties.name ?? node?.properties.hostname ?? node?.label;
}

/** Q119: candidates are review evidence and never version-match counts. */
export function cveCandidates(graph: GraphModel): Row[] {
  return graph.edges
    .filter(
      (edge) =>
        edge.kind.replace(/^rs_/, "").replaceAll("_", "").toLowerCase() === "hascvecandidate",
    )
    .map((edge) => {
      const subject = graph.nodeById.get(edge.source);
      const cve = graph.nodeById.get(edge.target);
      const p = edge.properties ?? {};
      return {
        subject: subjectName(subject),
        scan_id: subject?.properties.scan_id,
        cve_id: cve?.properties.cve_id,
        cpe: p.cpe,
        matched_criteria: p.matched_criteria,
        applicability: p.match_confidence,
        required_conditions: p.required_conditions,
        fetched_at: p.fetched_at,
        cache_stale: p.cache_stale,
        cache_complete: p.cache_complete,
        parser_version: p.parser_version,
        _node_id: subject?.id,
      };
    })
    .sort(
      byKeys(
        (row) => text(row.subject),
        (row) => text(row.cve_id),
      ),
    );
}

/** Q120: absent metadata means not assessed, never zero vulnerabilities. */
export function cveCoverage(graph: GraphModel): Row[] {
  return [...ofKind(graph, "Application"), ...ofKind(graph, "Computer")]
    .map((node) => ({
      subject: subjectName(node),
      scan_id: node.properties.scan_id,
      installed_version: node.properties.version ?? node.properties.macos_version,
      coverage: node.properties.nvd_coverage ?? "not_assessed",
      target_count: node.properties.nvd_target_count,
      cached_count: node.properties.nvd_cached_count,
      stale: node.properties.nvd_cache_stale,
      complete: node.properties.nvd_cache_complete,
      truncated: node.properties.nvd_cache_truncated,
      _node_id: node.id,
    }))
    .sort(
      byKeys(
        (row) => text(row.coverage),
        (row) => text(row.subject),
      ),
    );
}

type Setting = readonly [string, string, (value: unknown) => boolean];
const isTrue = (value: unknown): boolean => value === true;
const isFalse = (value: unknown): boolean => value === false;
const never = (): boolean => false;
const present = (value: unknown): boolean => value !== null && value !== undefined;

/** The settings of query 117 with the value that makes each one weak. */
const SETTINGS: readonly Setting[] = [
  ["Guest account enabled", "guest_account_enabled", isTrue],
  ["Automatic login user", "auto_login_user", present],
  ["Root account enabled", "root_account_enabled", isTrue],
  ["Remote Apple Events enabled", "remote_apple_events_enabled", isTrue],
  ["Remote Management enabled", "remote_management_enabled", isTrue],
  ["Software Update: automatic check", "software_update_automatic_check", isFalse],
  ["Software Update: automatic download", "software_update_automatic_download", isFalse],
  [
    "Software Update: install security responses",
    "software_update_install_security_responses",
    isFalse,
  ],
  ["Software Update: install macOS updates", "software_update_install_system_updates", isFalse],
  ["Software Update: install app updates", "software_update_install_app_updates", isFalse],
  ["Software Update: last successful check", "software_update_last_successful_check", never],
  ["XProtect version", "xprotect_version", never],
  ["XProtect Remediator version", "xprotect_remediator_version", never],
  ["MRT version", "mrt_version", never],
];

const ASSESSMENT_RANK: Record<string, number> = { weak: 0, unknown: 1, ok: 2 };

function assessment(host: ViewerNode, key: string, weak: (value: unknown) => boolean): string {
  const value = host.properties[key];
  if (weak(value)) return "weak";
  // Without an automatic login user the setting is known once the loginwindow plist was read.
  const known =
    present(value) || (key === "auto_login_user" && present(host.properties.guest_account_enabled));
  return known ? "ok" : "unknown";
}

/** Q117: one row per account, remote-control, Software Update and malware-protection setting. */
export function hostSecuritySettings(graph: GraphModel): Row[] {
  return ofKind(graph, "Computer")
    .flatMap((host) =>
      SETTINGS.map(([setting, key, weak], index) => {
        const value = host.properties[key];
        return {
          hostname: host.properties.hostname,
          setting,
          value: present(value) ? String(value) : null,
          assessment: assessment(host, key, weak),
          rank: index + 1,
          _node_id: host.id,
        };
      }),
    )
    .sort(
      byKeys(
        (row) => text(row.hostname),
        (row) => ASSESSMENT_RANK[text(row.assessment)] ?? 3,
        (row) => num(row.rank),
      ),
    );
}

const HOST_ANSWERS: Record<string, (graph: GraphModel) => Row[]> = {
  "104": installedSoftwareCves,
  "119": cveCandidates,
  "120": cveCoverage,
  "106": networkListeners,
  "107": trustedCertificates,
  "108": riskyExtensions,
  "109": launchdInjection,
  "110": stalePersistence,
  "111": userWritablePersistence,
  "117": hostSecuritySettings,
};

/** Rows for a host-evidence question, or undefined when the id is not one of them. */
export function hostAnswer(graph: GraphModel, question: string): Row[] | undefined {
  return Object.hasOwn(HOST_ANSWERS, question) ? HOST_ANSWERS[question]?.(graph) : undefined;
}

/** Identity columns a live query row shares with its node; a row matches only one node. */
const ROW_IDENTITIES: readonly (readonly [string, string][])[] = [
  [["sha256", "sha256"]],
  [
    ["plist_path", "path"],
    ["label", "label"],
  ],
  [
    ["extension_id", "extension_id"],
    ["profile", "profile"],
  ],
  [
    ["protocol", "protocol"],
    ["address", "address"],
    ["port", "port"],
    ["pid", "pid"],
  ],
];

function identityMatch(graph: GraphModel, row: Row): ViewerNode | undefined {
  for (const identity of ROW_IDENTITIES) {
    if (!identity.every(([column]) => row[column] !== undefined && row[column] !== null)) continue;
    const found = graph.nodes.filter((node) =>
      identity.every(([column, key]) => node.properties[key] === row[column]),
    );
    if (found.length === 1) return found[0];
  }
  return undefined;
}

/** The node a result row describes: the offline `_node_id`, else a unique identity match. */
export function resultNode(graph: GraphModel, row: Row): ViewerNode | undefined {
  if (typeof row._node_id === "string") return graph.nodeById.get(row._node_id);
  return identityMatch(graph, row);
}
