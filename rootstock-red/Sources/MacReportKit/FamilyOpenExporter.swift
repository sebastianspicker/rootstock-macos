import CryptoKit
import Foundation
import RootstockCore

/// Optional DD-011 family open-export (schema v1) for Neo4j import.
///
/// Not a full `scan.json`. Nodes and edges are allowlisted by the family graph importer.
public enum FamilyOpenExporter: Sendable {
    public static let schemaVersion = 1
    public static let source = "rootstock-red"

    public static let maxFindings = 200
    public static let maxLaunchItems = 50

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
        let hostId = nodeID(type: "Host", rawKey: hostname.isEmpty ? "unknown-host" : hostname)
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
        var seen = Set([hostId])

        appendProtections(state, hostId: hostId, nodes: &nodes, edges: &edges, seen: &seen)
        appendLaunchItems(state, hostId: hostId, nodes: &nodes, edges: &edges, seen: &seen)
        appendFindings(findings, hostId: hostId, nodes: &nodes, edges: &edges, seen: &seen)

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]

        var export: [String: Any] = [
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
        // The v1 schema allows extra top-level keys; only set when a cap cut items.
        if findings.count > maxFindings || state.launchAgents.count > maxLaunchItems { export["truncated"] = true }
        return export
    }

    private static func appendProtections(_ state: CollectedState, hostId: String, nodes: inout [[String: Any]], edges: inout [[String: String]], seen: inout Set<String>) {
        guard let protections = state.protections else { return }
        [("SIP", protections.sipEnabled), ("Gatekeeper", protections.gatekeeperEnabled), ("FileVault", protections.fileVaultOn)].forEach { appendProtection(name: $0.0, enabled: $0.1, hostId: hostId, nodes: &nodes, edges: &edges, seen: &seen) }
    }

    private static func appendLaunchItems(_ state: CollectedState, hostId: String, nodes: inout [[String: Any]], edges: inout [[String: String]], seen: inout Set<String>) {
        for item in state.launchAgents.prefix(maxLaunchItems) {
            let label = nonEmpty(item.label) ?? item.path
            let program = item.programArguments.first ?? ""
            let id = nodeID(type: "LaunchItem", rawKey: [label, item.path, program].joined(separator: "\u{1F}"))
            guard seen.insert(id).inserted else { continue }
            nodes.append(["id": id, "type": "LaunchItem", "name": label, "label": item.label ?? "", "path": item.path, "program": program])
            edges.append(["from": hostId, "to": id, "type": "HAS_LAUNCH_ITEM"])
        }
    }

    private static func appendFindings(_ findings: [Finding], hostId: String, nodes: inout [[String: Any]], edges: inout [[String: String]], seen: inout Set<String>) {
        for finding in findings.prefix(maxFindings) {
            let id = nodeID(type: "Finding", rawKey: finding.id)
            guard seen.insert(id).inserted else { continue }
            nodes.append(["id": id, "type": "Finding", "name": finding.title, "finding_id": finding.id, "severity": finding.severity.rawValue, "category": finding.category.rawValue, "confidence": finding.confidence.rawValue])
            edges.append(["from": hostId, "to": id, "type": "HAS_FINDING"])
        }
    }

    /// Writes the export and returns the number of Finding nodes written and whether a cap cut items.
    @discardableResult
    public static func writeJSON(
        findings: [Finding],
        state: CollectedState,
        to url: URL,
        scopeName: String = "rootstock-red-assess",
        scanProfile: String = "standard"
    ) throws -> (findings: Int, truncated: Bool) {
        let dict = build(
            findings: findings,
            state: state,
            scopeName: scopeName,
            scanProfile: scanProfile
        )
        let data = try JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: url, options: .atomic)
        let written = (dict["nodes"] as? [[String: Any]] ?? []).filter { $0["type"] as? String == "Finding" }.count
        return (written, dict["truncated"] as? Bool ?? false)
    }

    private static func appendProtection(
        name: String,
        enabled: Bool?,
        hostId: String,
        nodes: inout [[String: Any]],
        edges: inout [[String: String]],
        seen: inout Set<String>
    ) {
        let id = nodeID(type: "Protection", rawKey: name.lowercased())
        guard seen.insert(id).inserted else { return }
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

    /// Family open-export v1 identity rule: a readable normalized prefix plus
    /// SHA-256 of the canonical raw key. The digest avoids collisions caused by
    /// replacing distinct punctuation with the same readable character.
    private static func nodeID(type: String, rawKey: String) -> String {
        "\(type):\(readablePrefix(rawKey))--\(sha256(rawKey))"
    }

    private static func readablePrefix(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        let scalars = value.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" }
        let normalized = String(scalars)
        return normalized.isEmpty ? "item" : String(normalized.prefix(80))
    }

    private static func sha256(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        return value
    }
}
