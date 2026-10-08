/** Host evidence tables for the offline snapshot summary; a table appears only when its evidence is loaded. */
import { propertyValue } from "./runtime";
import type { GraphModel } from "./types";
import { hostSecuritySettings, installedSoftwareCves } from "./folio-host-answers";
import {
  codePointOrder,
  networkListeners,
  ofKind,
  riskyExtensions,
  text,
  trustedCertificates,
} from "./folio-host-questions";
import type { Row } from "./folio-host-questions";

export interface SummaryTable {
  title: string;
  note: string;
  columns: string[];
  rows: string[][];
  /** Rows left out of `rows` because of the row limit. */
  omitted: number;
}

const ROW_LIMIT = 50;

function cell(input: unknown): string {
  if (input === true) return "yes";
  if (input === false) return "no";
  if (Array.isArray(input) && input.length === 0) return "none";
  return propertyValue(input) || "not collected";
}

function table(
  title: string,
  note: string,
  columns: [string, (row: Row) => unknown][],
  rows: Row[],
): SummaryTable {
  return {
    title,
    note,
    columns: columns.map(([name]) => name),
    rows: rows.slice(0, ROW_LIMIT).map((row) => columns.map(([, read]) => cell(read(row)))),
    omitted: Math.max(0, rows.length - ROW_LIMIT),
  };
}

function settingsTable(graph: GraphModel): SummaryTable[] {
  const rows = hostSecuritySettings(graph);
  if (!rows.some((row) => row.assessment !== "unknown")) return [];
  return [
    table(
      "Host security settings",
      "Weak settings first. Unknown means the collector could not read the setting, not that it is safe.",
      [
        ["Host", (row) => row.hostname],
        ["Setting", (row) => row.setting],
        ["Value", (row) => row.value],
        ["Assessment", (row) => (row.assessment === "unknown" ? "not collected" : row.assessment)],
      ],
      rows,
    ),
  ];
}

function listenerTable(graph: GraphModel): SummaryTable[] {
  const rows = networkListeners(graph);
  if (!rows.length) return [];
  return [
    table(
      "Network listeners",
      "Observed listening sockets. Exposed means bound to a non-loopback address.",
      [
        [
          "Endpoint",
          (row) => `${text(row.protocol)} ${text(row.address)}:${propertyValue(row.port)}`,
        ],
        ["Exposed", (row) => row.exposed],
        ["Reachable without firewall", (row) => row.reachable_without_firewall],
        ["Process", (row) => row.process],
        ["User", (row) => row.user],
      ],
      rows,
    ),
  ];
}

function trustTable(graph: GraphModel): SummaryTable[] {
  const rows = trustedCertificates(graph);
  if (!rows.length) return [];
  return [
    table(
      "Trust store",
      "Certificates added to user or admin trust settings. A custom root can sign certificates for any website.",
      [
        ["Subject", (row) => row.subject],
        ["Domain", (row) => row.domain],
        ["Trust result", (row) => row.trust_result],
        ["Custom root", (row) => row.custom_root],
        ["Expires", (row) => row.not_after],
      ],
      rows,
    ),
  ];
}

function extensionTable(graph: GraphModel): SummaryTable[] {
  const total = ofKind(graph, "BrowserExtension").length;
  if (!total) return [];
  return [
    table(
      "Browser extensions",
      `${total} extension(s) recorded; listed are those with access to every site or installed from outside the store.`,
      [
        ["Browser", (row) => `${text(row.browser)} ${text(row.profile)}`.trim()],
        ["Extension", (row) => row.extension_name],
        ["Installed from", (row) => row.install_location],
        ["Every site", (row) => row.broad_host_access],
        ["Sensitive permissions", (row) => row.sensitive_permissions],
      ],
      riskyExtensions(graph),
    ),
  ];
}

function packageRows(graph: GraphModel): Row[] {
  return ofKind(graph, "InstalledPackage")
    .filter((node) => node.properties.is_apple !== true)
    .map((node) => node.properties)
    .sort((left, right) => codePointOrder(text(right.install_date), text(left.install_date)));
}

function packageTable(graph: GraphModel): SummaryTable[] {
  const total = ofKind(graph, "InstalledPackage").length;
  if (!total) return [];
  return [
    table(
      "Installed packages",
      `${total} installer receipt(s) recorded; listed are the non-Apple packages, newest first.`,
      [
        ["Package ID", (row) => row.package_id],
        ["Version", (row) => row.version],
        ["Installed", (row) => row.install_date],
        ["Installer process", (row) => row.install_process],
      ],
      packageRows(graph),
    ),
  ];
}

function macosCveNote(graph: GraphModel): string {
  const counts = ofKind(graph, "Computer")
    .filter((host) => typeof host.properties.macos_cve_count === "number")
    .map(
      (host) =>
        `macOS ${cell(host.properties.macos_version)}: ${propertyValue(host.properties.macos_cve_count)} CVE(s), ${cell(host.properties.macos_kev_cve_count)} in KEV.`,
    );
  return counts.join(" ");
}

function cveTable(graph: GraphModel): SummaryTable[] {
  const rows = installedSoftwareCves(graph);
  const macos = macosCveNote(graph);
  if (!rows.length && !macos) return [];
  return [
    table(
      "CVEs matched through NVD",
      `${macos} NVD lists these CVEs for the exact installed version (CPE match). A match is a published weakness, not evidence of exploitation.`.trim(),
      [
        ["Application", (row) => row.app_name],
        ["Version", (row) => row.app_version],
        ["CVEs", (row) => row.cve_count],
        ["KEV", (row) => row.kev_count],
        ["Max CVSS", (row) => row.max_cvss],
        ["Top CVEs", (row) => row.top_cves],
      ],
      rows,
    ),
  ];
}

/** Host evidence tables in report order; empty when the snapshot holds none of it. */
export function hostSummaryTables(graph: GraphModel): SummaryTable[] {
  return [
    ...settingsTable(graph),
    ...cveTable(graph),
    ...listenerTable(graph),
    ...trustTable(graph),
    ...extensionTable(graph),
    ...packageTable(graph),
  ];
}

const markdownCell = (input: string): string =>
  input
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replace(/[\r\n]+/g, " ");

function markdownTable(summary: SummaryTable): string[] {
  const lines = [
    "",
    `## ${summary.title}`,
    summary.note,
    "",
    `| ${summary.columns.join(" | ")} |`,
    `| ${summary.columns.map(() => "---").join(" | ")} |`,
    ...summary.rows.map((row) => `| ${row.map(markdownCell).join(" | ")} |`),
  ];
  if (!summary.rows.length) lines.splice(4, 2, "No rows match in the loaded snapshot.");
  if (summary.omitted) lines.push("", `${summary.omitted} more row(s) in the loaded snapshot.`);
  return lines;
}

export function hostSummaryMarkdown(graph: GraphModel): string[] {
  return hostSummaryTables(graph).flatMap(markdownTable);
}
