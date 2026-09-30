import CryptoKit
import Foundation
import RootstockBlueCase
import RootstockBlueCore

/// Optional DD-011 family open-export (schema v1) for Neo4j import from a case.
public enum FamilyOpenExporter: Sendable {
    public static let schemaVersion = 1
    public static let source = "rootstock-blue"

    public static let nodeTypes = ["Finding", "Host", "LaunchItem", "Protection"]
    public static let edgeVocabulary = ["HAS_FINDING", "HAS_LAUNCH_ITEM", "HAS_PROTECTION"]

    /// Build export from case timeline events (subset: host + protections + persistence + findings).
    public static func build(
        events: [EventEnvelope],
        caseName: String = "case",
        scopeName: String = "rootstock-blue-case",
        scanProfile: String = "offline-dfir",
        generatedAt: Date = Date()
    ) -> [String: Any] {
        let hostName = hostName(from: events, fallback: caseName)
        var graph = FamilyOpenGraph(hostName: hostName, caseName: caseName)
        for event in events {
            graph.append(event)
        }
        return graph.export(scopeName: scopeName, scanProfile: scanProfile, generatedAt: generatedAt)
    }

    private struct FamilyOpenGraph {
        let hostName: String
        let hostID: String
        let caseName: String
        var nodes: [[String: Any]]
        var edges: [[String: String]] = []
        var seen = Set<String>()

        init(hostName: String, caseName: String) {
            self.hostName = hostName
            self.hostID = FamilyOpenExporter.nodeID(type: "Host", rawKey: hostName)
            self.caseName = caseName
            self.nodes = [["id": hostID, "type": "Host", "name": hostName, "hostname": hostName, "case_name": caseName]]
        }

        mutating func append(_ event: EventEnvelope) {
            if event.eventType == EventVocabulary.postureProtection {
                appendProtection(event)
            } else if EventVocabulary.isPersistence(event.eventType) || event.sourcePlugin == "AUTOSTART" {
                appendLaunchItem(event)
            } else if event.eventType == EventVocabulary.importedFinding || event.eventType.hasPrefix("harden.") || event.fields["finding.id"] != nil {
                appendFinding(event)
            }
        }

        mutating func appendProtection(_ event: EventEnvelope) {
            let name = event.fields["protection.name"] ?? "Protection"
            let id = FamilyOpenExporter.nodeID(type: "Protection", rawKey: name.lowercased())
            guard seen.insert(id).inserted else { return }
            nodes.append(["id": id, "type": "Protection", "name": name, "enabled": event.fields["protection.enabled"] ?? "unknown"])
            edges.append(["from": hostID, "to": id, "type": "HAS_PROTECTION"])
        }

        mutating func appendLaunchItem(_ event: EventEnvelope) {
            let label = nonEmpty(event.fields[FieldTaxonomy.persistenceLabel])
                ?? nonEmpty(event.rawRef)
                ?? event.id.uuidString
            let path = event.fields[FieldTaxonomy.persistencePath] ?? ""
            let program = event.fields[FieldTaxonomy.persistenceProgram] ?? event.fields[FieldTaxonomy.processPath] ?? ""
            let id = FamilyOpenExporter.nodeID(
                type: "LaunchItem",
                rawKey: [label, path, program].joined(separator: "\u{1F}")
            )
            guard seen.insert(id).inserted else { return }
            nodes.append(["id": id, "type": "LaunchItem", "name": label, "label": label, "path": path, "program": program])
            edges.append(["from": hostID, "to": id, "type": "HAS_LAUNCH_ITEM"])
        }

        mutating func appendFinding(_ event: EventEnvelope) {
            let findingID = nonEmpty(event.fields["finding.id"]) ?? event.id.uuidString
            let id = FamilyOpenExporter.nodeID(type: "Finding", rawKey: findingID)
            guard seen.insert(id).inserted else { return }
            nodes.append(["id": id, "type": "Finding", "name": event.fields["finding.title"] ?? findingID, "finding_id": findingID, "severity": event.fields["finding.severity"] ?? "info", "category": event.fields["finding.category"] ?? "other"])
            edges.append(["from": hostID, "to": id, "type": "HAS_FINDING"])
        }

        func export(scopeName: String, scanProfile: String, generatedAt: Date) -> [String: Any] {
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime]
            return ["schema_version": FamilyOpenExporter.schemaVersion, "source": FamilyOpenExporter.source, "generated_at": formatter.string(from: generatedAt), "scope_name": scopeName, "scan_profile": scanProfile, "node_types": FamilyOpenExporter.nodeTypes, "edge_types": Array(Set(edges.map { $0["type"]! })).sorted(), "edge_vocabulary": FamilyOpenExporter.edgeVocabulary, "nodes": nodes, "edges": edges]
        }
    }

    public static func writeJSON(
        events: [EventEnvelope],
        to url: URL,
        caseName: String = "case",
        scopeName: String = "rootstock-blue-case"
    ) throws {
        let dict = build(events: events, caseName: caseName, scopeName: scopeName)
        let data = try JSONSerialization.data(
            withJSONObject: dict,
            options: [.prettyPrinted, .sortedKeys]
        )
        try CaseOutputWriter.write(data, to: url)
    }

    /// Case-aware export path: verify before reading and publish outside the
    /// package with staged, no-clobber semantics.
    @discardableResult
    public static func writeJSON(
        from package: CasePackage,
        to url: URL,
        scopeName: String = "rootstock-blue-case"
    ) throws -> Int {
        try package.verifyIntegrity()
        let events = try package.loadAllEvents()
        let dict = build(events: events, caseName: package.manifest.name, scopeName: scopeName)
        let data = try JSONSerialization.data(
            withJSONObject: dict,
            options: [.prettyPrinted, .sortedKeys]
        )
        try CaseOutputWriter.write(data, from: package, to: url)
        return events.count
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

    private static func hostName(from events: [EventEnvelope], fallback: String) -> String {
        for event in events where event.eventType == EventVocabulary.postureHost || event.eventType == EventVocabulary.collectorScanMeta {
            if let hostName = event.fields["host.hostname"] ?? event.fields["collector.hostname"], !hostName.isEmpty {
                return hostName
            }
        }
        return fallback
    }
}
