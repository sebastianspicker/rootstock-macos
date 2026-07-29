import Foundation
import RootstockCore

/// Optional DD-011 family open-export (schema v1) for Neo4j import.
///
/// Not a full `scan.json`. Nodes/edges are allowlisted for `graph/import_family_export.py`.
public enum FamilyOpenExporter: Sendable {
    public static let schemaVersion = 1
    public static let source = "rootstock-red"

    public static let nodeTypes = ["Finding", "Host", "LaunchItem", "Protection"]
    public static let edgeVocabulary = ["HAS_FINDING", "HAS_LAUNCH_ITEM", "HAS_PROTECTION"]

    /// Build export dictionary from assessment state + findings.
    public static func build(
        findings: [Finding],
        state: CollectedState,
        scopeName: String = "rootstock-red-assess",
        scanProfile: String = "standard",
        generatedAt: Date = Date()
    ) -> [String: Any] {
        let hostname = state.host?.hostname ?? "unknown-host"
        let osVersion = state.host?.osVersion ?? ""
        let hostId = "Host:\(sanitize(hostname.isEmpty ? "unknown-host" : hostname))"
        var nodes: [[String: Any]] = [
            [
                "id": hostId,
                "type": "Host",
                "name": hostname,
                "hostname": hostname,
                "os_version": osVersion,
            ],
        ]
        var edges: [[String: String]] = []

        appendProtections(state, hostId: hostId, nodes: &nodes, edges: &edges)
        appendLaunchItems(state, hostId: hostId, nodes: &nodes, edges: &edges)
        appendFindings(findings, hostId: hostId, nodes: &nodes, edges: &edges)

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]

        return [
            "schema_version": schemaVersion,
            "source": source,
            "generated_at": formatter.string(from: generatedAt),
            "scope_name": scopeName,
            "scan_profile": scanProfile,
            "node_types": nodeTypes,
            "edge_types": Array(Set(edges.map(\.["type"]!))).sorted(),
            "edge_vocabulary": edgeVocabulary,
            "nodes": nodes,
            "edges": edges,
        ]
    }

    private static func appendProtections(_ state: CollectedState, hostId: String, nodes: inout [[String: Any]], edges: inout [[String: String]]) {
        guard let protections = state.protections else { return }
        [("SIP", protections.sipEnabled), ("Gatekeeper", protections.gatekeeperEnabled), ("FileVault", protections.fileVaultOn)].forEach { appendProtection(name: $0.0, enabled: $0.1, hostId: hostId, nodes: &nodes, edges: &edges) }
    }

    private static func appendLaunchItems(_ state: CollectedState, hostId: String, nodes: inout [[String: Any]], edges: inout [[String: String]]) {
        for item in state.launchAgents.prefix(50) {
            let id = "LaunchItem:\(sanitize(item.label ?? item.path))"
            nodes.append(["id": id, "type": "LaunchItem", "name": item.label ?? item.path, "label": item.label ?? "", "path": item.path, "program": item.programArguments.first ?? ""])
            edges.append(["from": hostId, "to": id, "type": "HAS_LAUNCH_ITEM"])
        }
    }

    private static func appendFindings(_ findings: [Finding], hostId: String, nodes: inout [[String: Any]], edges: inout [[String: String]]) {
        for finding in findings.prefix(200) {
            let id = "Finding:\(sanitize(finding.id))"
            nodes.append(["id": id, "type": "Finding", "name": finding.title, "finding_id": finding.id, "severity": finding.severity.rawValue, "category": finding.category.rawValue, "confidence": finding.confidence.rawValue])
            edges.append(["from": hostId, "to": id, "type": "HAS_FINDING"])
        }
    }

    public static func writeJSON(
        findings: [Finding],
        state: CollectedState,
        to url: URL,
        scopeName: String = "rootstock-red-assess",
        scanProfile: String = "standard"
    ) throws {
        let dict = build(
            findings: findings,
            state: state,
            scopeName: scopeName,
            scanProfile: scanProfile
        )
        let data = try JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: url, options: .atomic)
    }

    private static func appendProtection(
        name: String,
        enabled: Bool?,
        hostId: String,
        nodes: inout [[String: Any]],
        edges: inout [[String: String]]
    ) {
        let id = "Protection:\(sanitize(name.lowercased()))"
        let label: String
        switch enabled {
        case .some(true): label = "true"
        case .some(false): label = "false"
        case .none: label = "unknown"
        }
        nodes.append(
            [
                "id": id,
                "type": "Protection",
                "name": name,
                "enabled": label,
            ]
        )
        edges.append(["from": hostId, "to": id, "type": "HAS_PROTECTION"])
    }

    private static func sanitize(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        let scalars = value.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" }
        return String(scalars)
    }
}
