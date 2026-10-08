/** Kind-specific key facts for the inspector's Evidence tab, in the order an analyst reads them. */

import { element, propertyValue } from "./runtime";
import type { ViewerNode } from "./types";

/** [label, property, flag]: a flagged row is highlighted when its value is present and not false. */
type FactSpec = readonly [string, string, boolean?];

interface FactGroup {
  title: string;
  facts: readonly FactSpec[];
  /** Show absent values as "Not collected" instead of omitting the row. */
  showMissing?: boolean;
}

const HOST_SETTINGS: FactGroup = {
  title: "Host settings",
  showMissing: true,
  facts: [
    ["Guest account enabled", "guest_account_enabled", true],
    ["Automatic login user", "auto_login_user", true],
    ["Root account enabled", "root_account_enabled", true],
    ["Remote Apple Events", "remote_apple_events_enabled", true],
    ["Remote Management", "remote_management_enabled", true],
    ["Update: automatic check", "software_update_automatic_check"],
    ["Update: automatic download", "software_update_automatic_download"],
    ["Update: security responses", "software_update_install_security_responses"],
    ["Update: macOS updates", "software_update_install_system_updates"],
    ["Update: app updates", "software_update_install_app_updates"],
    ["Update: last successful check", "software_update_last_successful_check"],
    ["XProtect version", "xprotect_version"],
    ["XProtect Remediator version", "xprotect_remediator_version"],
    ["MRT version", "mrt_version"],
    ["DNS servers", "dns_servers"],
    ["Search domains", "search_domains"],
    ["Proxies", "proxy_settings"],
    ["Hosts file entries", "hosts_entries"],
    ["macOS CVEs (NVD)", "macos_cve_count"],
    ["macOS CVEs in KEV", "macos_kev_cve_count", true],
  ],
};

const FACT_GROUPS: Record<string, FactGroup[]> = {
  rs_Computer: [HOST_SETTINGS],
  rs_LaunchItem: [
    {
      title: "Launch item",
      facts: [
        ["Program", "program"],
        ["Arguments", "program_arguments"],
        ["DYLD environment", "dyld_environment", true],
        ["Environment variables", "environment_variable_names"],
        ["Triggers", "triggers"],
        ["Interval (seconds)", "interval_seconds"],
        ["Session type", "session_type"],
        ["Loaded", "loaded"],
        ["Disabled in plist", "disabled"],
        ["Program exists", "program_exists"],
        ["Program SHA-256", "program_sha256"],
        ["Plist modified", "plist_modified"],
        ["Inside app bundle", "bundle_path"],
      ],
    },
  ],
  rs_Application: [
    {
      title: "Executable",
      facts: [
        ["Executable", "executable_path"],
        ["Executable SHA-256", "executable_sha256"],
        ["Downloaded from", "origin_host"],
      ],
    },
  ],
  rs_NetworkListener: [
    {
      title: "Listener",
      facts: [
        ["Endpoint", "endpoint"],
        ["State", "state"],
        ["Exposed beyond loopback", "exposed", true],
        ["Reachable without firewall", "reachable_without_firewall", true],
        ["Application firewall on", "firewall_enabled"],
        ["Process", "process_name"],
        ["PID", "pid"],
        ["User", "user"],
        ["Bundle ID", "bundle_id"],
      ],
    },
  ],
  rs_TrustedCertificate: [
    {
      title: "Certificate",
      facts: [
        ["Subject", "subject"],
        ["Issuer", "issuer"],
        ["Trust domain", "domain"],
        ["Trust result", "trust_result"],
        ["Custom root", "custom_root", true],
        ["Self-signed", "is_self_signed"],
        ["Expires", "not_after"],
        ["SHA-256", "sha256"],
      ],
    },
  ],
  rs_BrowserExtension: [
    {
      title: "Extension",
      facts: [
        ["Browser", "browser"],
        ["Profile", "profile"],
        ["Version", "version"],
        ["Installed from", "install_location"],
        ["From the store", "from_webstore"],
        ["Enabled", "enabled"],
        ["Access to every site", "broad_host_access", true],
        ["Sensitive permissions", "sensitive_permissions", true],
        ["Site access", "host_permissions"],
        ["Installed", "install_time"],
      ],
    },
  ],
  rs_InstalledPackage: [
    {
      title: "Package receipt",
      facts: [
        ["Package ID", "package_id"],
        ["Version", "version"],
        ["Installed", "install_date"],
        ["Installer process", "install_process"],
        ["Package file", "package_file_name"],
        ["Install prefix", "install_prefix"],
        ["Apple package", "is_apple"],
      ],
    },
  ],
  rs_Process: [
    {
      title: "Process",
      facts: [
        ["PID", "pid"],
        ["Parent PID", "ppid"],
        ["User", "user"],
        ["Command", "command"],
        ["Runs from a user-writable location", "command_in_user_writable_location", true],
        ["Bundle ID", "bundle_id"],
      ],
    },
  ],
};

/** Properties a key-fact group already shows, so the raw rows below do not repeat them. */
export function factPropertyKeys(kind: string): Set<string> {
  return new Set((FACT_GROUPS[kind] ?? []).flatMap((group) => group.facts.map(([, key]) => key)));
}

function missing(value: unknown): boolean {
  return value === null || value === undefined || value === "";
}

export function factText(value: unknown): string {
  if (value === true) return "Yes";
  if (value === false) return "No";
  if (Array.isArray(value) && value.length === 0) return "None";
  return propertyValue(value);
}

function flagged(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  return value !== false && value !== 0 && !missing(value);
}

function factRow(label: string, value: unknown, flag: boolean): HTMLElement {
  const absent = missing(value);
  const highlight = flag && flagged(value);
  const className = absent
    ? "prop-row fact-missing"
    : highlight
      ? "prop-row fact-flag"
      : "prop-row";
  return element("div", { class: className }, [
    element("span", { class: "prop-key", text: label }),
    element("span", { class: "prop-val", text: absent ? "Not collected" : factText(value) }),
  ]);
}

function groupRows(node: ViewerNode, group: FactGroup): HTMLElement[] {
  return group.facts
    .filter(([, key]) => group.showMissing === true || !missing(node.properties[key]))
    .map(([label, key, flag]) => factRow(label, node.properties[key], flag === true));
}

/** Heading plus rows per group; groups without any recorded value are left out. */
export function keyFacts(node: ViewerNode): HTMLElement[] {
  return (FACT_GROUPS[node.kind] ?? []).flatMap((group) => {
    const rows = groupRows(node, group);
    if (!rows.length) return [];
    return [element("h4", { text: group.title }), element("div", { class: "key-facts" }, rows)];
  });
}
