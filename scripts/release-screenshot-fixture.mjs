/**
 * Supplies deterministic, synthetic graph data for privacy-safe release screenshots.
 * It deliberately contains no scan-derived host data.
 */

export const VIEWPORT = {width: 1586, height: 992};
export const GENERATED_AT = "2026-07-16T00:00:00Z";
export const RELEASE_SCREENSHOT_OUTPUTS = {
  overview: "viewer-overview.png",
  inspector: "viewer-node-inspector.png",
  path: "viewer-attack-path.png",
  risk: "viewer-risk-filter.png",
};

function node(id, kind, label, x, y, color, riskLevel, properties) {
  return {
    id,
    kind,
    label,
    x,
    y,
    properties: {
      ...properties,
      _color: color,
      risk_level: riskLevel,
      evidence: "synthetic fixture",
    },
  };
}

function edge(source, target, kind, traversable) {
  return {
    source,
    target,
    kind,
    properties: {_traversable: traversable, evidence: "synthetic fixture"},
  };
}

export const fixture = {
  metadata: {
    hostname: "synthetic-alpha-fixture",
    generated_at: GENERATED_AT,
    collected_at: "2026-07-15T23:59:24Z",
    imported_at: "2026-07-15T23:59:40Z",
    derived_at: "2026-07-15T23:59:54Z",
    source: "public-release-screenshot-fixture",
  },
  graph: {
    nodes: [
      node("entry", "rs_Application", "Unsigned Helper", 180, 230, "#58a6ff", "medium", {asset_class: "application", signed: false}),
      node("target", "rs_Application", "Privileged Editor", 410, 130, "#58a6ff", "high", {asset_class: "application", library_validation: false}),
      node("launch", "rs_LaunchItem", "Login Persistence", 400, 340, "#d29922", "medium", {asset_class: "persistence"}),
      node("keychain", "rs_KeychainItem", "Shared Credential", 650, 130, "#bc8cff", "critical", {asset_class: "credential metadata"}),
      node("permission", "rs_TCCPermission", "Full Disk Access", 650, 340, "#f47067", "critical", {asset_class: "privacy permission"}),
      node("critical", "rs_CriticalFile", "Protected Configuration", 900, 230, "#f778ba", "critical", {asset_class: "critical file"}),
      node("recommendation", "rs_Recommendation", "Enable Library Validation", 900, 470, "#3fb950", "low", {asset_class: "remediation"}),
    ],
    edges: [
      edge("entry", "target", "rs_CanInjectInto", true),
      edge("entry", "launch", "rs_PersistsVia", true),
      edge("target", "keychain", "rs_CanReadKeychain", true),
      edge("target", "permission", "rs_HasTCCGrant", true),
      edge("target", "critical", "rs_CanWrite", true),
      edge("entry", "critical", "rs_CanWrite", true),
      edge("target", "recommendation", "rs_HasRecommendation", false),
    ],
  },
};
