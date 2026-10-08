/** Synthetic host evidence for the public demo: processes, a listener, trust, extension, receipt, NVD match. */

export const DEMO_SCAN_ID = "synthetic-scan-0001";

const HELPER_COMMAND = "/Users/Shared/SyntheticVNC/synthetic-vnc-helper";
const BROWSER_COMMAND = "/Applications/Synthetic Browser.app/Contents/MacOS/Synthetic Browser";
const ROOT_SHA256 = "5e".repeat(32);

/** Observed host evidence carries no risk score: only applications and the host are scored. */
function evidenceNode(evidence, id, kind, label, x, y, color, evidenceId, properties) {
  return {
    id,
    kind,
    label,
    x,
    y,
    properties: {
      ...properties,
      _color: color,
      evidence,
      evidence_id: evidenceId,
      evidence_class: "synthetic",
    },
  };
}

function observedEdge(evidence, source, target, kind, traversable, evidenceId, properties = {}) {
  return {
    source,
    target,
    kind,
    properties: {
      ...properties,
      _traversable: traversable,
      inferred: false,
      evidence,
      evidence_id: evidenceId,
      evidence_class: "synthetic",
    },
  };
}

function processNodes(evidence) {
  const process = (id, label, x, evidenceId, properties) =>
    evidenceNode(evidence, id, "rs_Process", label, x, 1_000, "#9e86ff", evidenceId, {
      scan_id: DEMO_SCAN_ID,
      user: "synthetic-user",
      ...properties,
    });
  return [
    process("demo-shell-process", "/bin/zsh", 120, "SYN-GLB-N20", {
      pid: 4100,
      ppid: 1,
      command: "/bin/zsh",
      command_in_user_writable_location: false,
    }),
    process("demo-vnc-helper", HELPER_COMMAND, 340, "SYN-GLB-N21", {
      pid: 4242,
      ppid: 4100,
      command: HELPER_COMMAND,
      command_in_user_writable_location: true,
    }),
    process("demo-browser-process", BROWSER_COMMAND, 1_000, "SYN-GLB-N22", {
      pid: 4300,
      ppid: 1,
      command: BROWSER_COMMAND,
      bundle_id: "com.example.synthetic-browser",
      command_in_user_writable_location: false,
    }),
  ];
}

function inventoryNodes(evidence) {
  const node = (...args) => evidenceNode(evidence, ...args);
  return [
    node(
      "demo-vnc-listener",
      "rs_NetworkListener",
      "tcp 0.0.0.0:5900",
      560,
      1_000,
      "#ec6cb9",
      "SYN-GLB-N23",
      {
        scan_id: DEMO_SCAN_ID,
        endpoint: "tcp 0.0.0.0:5900",
        protocol: "tcp",
        address: "0.0.0.0",
        port: 5900,
        is_loopback: false,
        state: "listen",
        pid: 4242,
        process_name: HELPER_COMMAND,
        user: "synthetic-user",
        exposed: true,
        firewall_enabled: false,
        reachable_without_firewall: true,
      },
    ),
    node(
      "demo-root-ca",
      "rs_TrustedCertificate",
      "Synthetic Inspection Root",
      120,
      1_180,
      "#f2a93b",
      "SYN-GLB-N24",
      {
        scan_id: DEMO_SCAN_ID,
        sha256: ROOT_SHA256,
        subject: "Synthetic Inspection Root",
        issuer: "Synthetic Inspection Root",
        domain: "admin",
        trust_result: "trust_root",
        is_self_signed: true,
        not_after: "2036-01-01T00:00:00Z",
        custom_root: true,
      },
    ),
    node(
      "demo-signing-ca",
      "rs_CertAuthority",
      "Synthetic Inspection Root (signing chain)",
      340,
      1_180,
      "#d2a8ff",
      "SYN-GLB-N25",
      {
        common_name: "Synthetic Inspection Root",
        sha256: ROOT_SHA256,
      },
    ),
    node(
      "demo-page-helper",
      "rs_BrowserExtension",
      "Synthetic Page Helper",
      1_250,
      1_000,
      "#4ac1a2",
      "SYN-GLB-N26",
      {
        scan_id: DEMO_SCAN_ID,
        browser: "chrome",
        profile: "Default",
        extension_id: "abcdefghijklmnopabcdefghijklmnop",
        name: "Synthetic Page Helper",
        version: "0.9.0",
        manifest_version: 3,
        permissions: ["cookies", "storage", "webRequest"],
        host_permissions: ["<all_urls>"],
        from_webstore: false,
        enabled: true,
        install_time: "2026-08-27T18:20:00Z",
        install_location: "unpacked",
        path: "/Users/synthetic-user/Synthetic Extensions/page-helper",
        broad_host_access: true,
        sensitive_permissions: ["cookies", "webRequest"],
      },
    ),
    node(
      "demo-browser-receipt",
      "rs_InstalledPackage",
      "com.example.synthetic-browser.pkg",
      1_250,
      1_180,
      "#a8b1ff",
      "SYN-GLB-N27",
      {
        scan_id: DEMO_SCAN_ID,
        package_id: "com.example.synthetic-browser.pkg",
        version: "120.0.1",
        install_date: "2026-08-28T09:30:00Z",
        install_prefix: "/",
        install_process: "installer",
        package_file_name: "SyntheticBrowser-120.0.1.pkg",
        is_apple: false,
      },
    ),
  ];
}

function browserNodes(evidence) {
  return [
    evidenceNode(
      evidence,
      "demo-browser-app",
      "rs_Application",
      "Synthetic Browser (synthetic)",
      1_000,
      1_180,
      "#58a6ff",
      "SYN-GLB-N28",
      {
        name: "Synthetic Browser",
        bundle_id: "com.example.synthetic-browser",
        path: "/Applications/Synthetic Browser.app",
        version: "120.0.1",
        executable_path: BROWSER_COMMAND,
        executable_sha256: "b7".repeat(32),
        origin_host: "downloads.example.invalid",
        risk_level: "high",
        risk_score: 7,
        risk_reasons: [
          "Installed version matches CVE-2026-22222 (synthetic NVD match)",
          "Was running when the scan was taken",
        ],
      },
    ),
    evidenceNode(
      evidence,
      "demo-nvd-cve",
      "rs_Vulnerability",
      "CVE-2026-22222 (synthetic NVD match)",
      1_400,
      1_180,
      "#f85149",
      "SYN-GLB-N29",
      {
        cve_id: "CVE-2026-22222",
        source: "nvd",
        cvss_score: 8.8,
        cvss_severity: "HIGH",
        in_kev: false,
        published: "2026-07-01T00:00:00Z",
        not_a_live_cve_claim: true,
      },
    ),
    evidenceNode(
      evidence,
      "demo-dyld-agent",
      "rs_LaunchItem",
      "com.fixture.helper.agent",
      560,
      1_180,
      "#d29922",
      "SYN-GLB-N30",
      {
        label: "com.fixture.helper.agent",
        path: "/Library/LaunchAgents/com.fixture.helper.agent.plist",
        type: "agent",
        program: "/Applications/Fixture Helper.app/Contents/MacOS/helper",
        program_arguments: [
          "/Applications/Fixture Helper.app/Contents/MacOS/helper",
          "--background",
        ],
        environment_variable_names: ["DYLD_INSERT_LIBRARIES"],
        dyld_environment: ["DYLD_INSERT_LIBRARIES=/Users/Shared/libsynthetic-hook.dylib"],
        triggers: ["start_interval"],
        interval_seconds: 3600,
        run_at_load: true,
        disabled: false,
        loaded: true,
        program_exists: true,
        program_sha256: "ab".repeat(32),
        plist_modified: "2026-08-29T21:14:00Z",
        plist_writable_by_non_root: false,
      },
    ),
  ];
}

function hostEdges(evidence) {
  const edge = (...args) => observedEdge(evidence, ...args);
  return [
    edge("demo-shell-process", "demo-vnc-helper", "rs_ParentOf", false, "SYN-GLB-E21"),
    edge("demo-browser-process", "demo-browser-app", "rs_InstanceOf", false, "SYN-GLB-E22"),
    edge("demo-vnc-helper", "demo-host", "rs_RunsOn", false, "SYN-GLB-E23"),
    edge("demo-vnc-helper", "demo-vnc-listener", "rs_ListensOn", false, "SYN-GLB-E24"),
    edge("demo-vnc-listener", "demo-host", "rs_ExposedOn", false, "SYN-GLB-E25"),
    edge("demo-host", "demo-root-ca", "rs_TrustsCertificate", false, "SYN-GLB-E26"),
    edge("demo-root-ca", "demo-signing-ca", "rs_SameCertificate", false, "SYN-GLB-E27"),
    edge("demo-xpc", "demo-signing-ca", "rs_SignedByCA", false, "SYN-GLB-E28"),
    edge("demo-browser-app", "demo-page-helper", "rs_HasExtension", false, "SYN-GLB-E29"),
    edge("demo-browser-app", "demo-browser-receipt", "rs_InstalledBy", false, "SYN-GLB-E30"),
    edge("demo-browser-receipt", "demo-host", "rs_InstalledOn", false, "SYN-GLB-E31"),
    edge("demo-browser-app", "demo-nvd-cve", "rs_AffectedBy", true, "SYN-GLB-E32", {
      match_tier: "cpe",
      match_source: "nvd",
      cpe: "cpe:2.3:a:example:synthetic_browser:120.0.1:*:*:*:*:*:*:*",
    }),
    edge("demo-helper", "demo-dyld-agent", "rs_PersistsVia", true, "SYN-GLB-E33"),
  ];
}

/** Nodes and edges added to the demo graph; ids continue the SYN-GLB numbering. */
export function hostEvidence(evidence) {
  return {
    nodes: [...processNodes(evidence), ...inventoryNodes(evidence), ...browserNodes(evidence)],
    edges: hostEdges(evidence),
  };
}

/** Collected host settings for the synthetic Computer node (flattened as the graph import does). */
export const DEMO_HOST_SETTINGS = {
  scan_id: DEMO_SCAN_ID,
  macos_version: "15.3",
  guest_account_enabled: false,
  root_account_enabled: false,
  remote_apple_events_enabled: false,
  remote_management_enabled: false,
  software_update_automatic_check: true,
  software_update_automatic_download: true,
  software_update_install_security_responses: true,
  software_update_install_system_updates: false,
  software_update_install_app_updates: true,
  software_update_last_successful_check: "2026-08-29T06:00:00Z",
  xprotect_version: "5290",
  xprotect_remediator_version: "145",
  mrt_version: "1.93",
  dns_servers: ["10.0.0.53"],
  search_domains: ["lab.example.invalid"],
  proxy_settings: [],
  proxy_count: 0,
  hosts_entries: [],
  hosts_entry_count: 0,
  stale_launch_item_count: 0,
  launchd_env_injection_count: 1,
  macos_cve_count: 12,
  macos_kev_cve_count: 1,
};
