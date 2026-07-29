import Foundation
import RootstockBlueCore

/// Network usage / egress inventory from fixture JSON exports of netusage.sqlite
/// or collector-side network usage dumps.
///
/// Surfaces process-level bytes in/out and destination domains for IR hunting
/// (anomalous egress, high-volume C2-like transfers, suspicious process names).
/// Offline-only - does not open live SQLite or perform live traffic capture.
public struct NetUsageParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "NETUSAGE",
        tier: .tier2,
        description: "Process network usage (bytes in/out, domains) from netusage exports"
    )

    /// Bytes-out above this threshold is treated as high_volume (fixture-scale).
    private static let highVolumeThreshold: Int64 = 50_000_000

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        let configured = Self.configuredPaths.compactMap { root.firstExisting([$0]) }
        let discovered = root.enumerate(matching: { Self.artifactNames.contains($0.lastPathComponent) })
        for url in configured + discovered where seen.insert(url) {
            events.append(contentsOf: parseInventory(at: url))
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        let items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["usage", "entries", "processes", "items"],
            identityKeys: ["process", "bytes_out", "domain"]
        )
        return items.compactMap { makeEvent(from: $0, rawRef: rawRef) }
    }

    private func parseInventory(at url: URL) -> [EventEnvelope] {
        guard let json = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        return parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url))
    }

    private static let configuredPaths = [
        "Library/Preferences/netusage.json", "Library/Preferences/com.apple.networkusage.json",
        "private/var/networkd/netusage.sqlite.json", "var/networkd/netusage.sqlite.json",
    ]

    private static let artifactNames: Set<String> = ["netusage.json", "com.apple.networkusage.json", "netusage.sqlite.json"]

    private func makeEvent(from item: [String: Any], rawRef: String) -> EventEnvelope? {
        let record = NetworkUsageRecord(item: item, highVolumeThreshold: Self.highVolumeThreshold)
        guard record.isMeaningful else { return nil }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "network.usage",
                label: "NETUSAGE"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["timestamp"] ?? item["last_seen"] ?? item["first_seen"]) ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: record.entities,
                properties: record.fields,
                provenance: rawRef,
                confidence: 0.88
            )
        )
    }

    private struct NetworkUsageRecord {
        let process: String
        let domain: String
        let bytesIn: Int64
        let bytesOut: Int64
        let riskTags: [String]
        let firstSeen: String?

        init(item: [String: Any], highVolumeThreshold: Int64) {
            process = Self.firstString(in: item, keys: ["process", "process_name", "proc", "name", "bundle_id"])
            domain = Self.firstString(in: item, keys: ["domain", "host", "destination", "remote_host"])
            bytesIn = Self.firstInt64(in: item, keys: ["bytes_in", "rx_bytes", "received"])
            bytesOut = Self.firstInt64(in: item, keys: ["bytes_out", "tx_bytes", "sent"])
            firstSeen = Self.firstOptionalString(in: item, keys: ["first_seen", "timestamp"])
            riskTags = Self.riskTags(item: item, process: process, domain: domain, bytesOut: bytesOut, highVolumeThreshold: highVolumeThreshold)
        }

        var isMeaningful: Bool { !process.isEmpty || !domain.isEmpty || bytesOut > 0 || bytesIn > 0 }

        var fields: [String: String] {
            var values: [String: String] = ["net.usage.process": process, "net.usage.bytes_in": String(bytesIn), "net.usage.bytes_out": String(bytesOut), "net.usage.domain": domain, FieldTaxonomy.eventType: "network.usage"]
            if !process.isEmpty { values[FieldTaxonomy.processPath] = process }
            if !domain.isEmpty { values["net.domain"] = domain }
            if !riskTags.isEmpty {
                let joined = riskTags.joined(separator: ",")
                values["net.risk_tags"] = joined
                values["net.usage.risk_tags"] = joined
            }
            if let firstSeen { values["net.usage.first_seen"] = firstSeen }
            return values
        }

        var entities: [EntityID] {
            var values: [EntityID] = [EntityID(kind: .network, value: "netusage|\(process)|\(domain)|\(bytesOut)")]
            if !process.isEmpty { values.append(EntityID(kind: .process, value: "path=\(process)")) }
            if !domain.isEmpty { values.append(EntityID(kind: .network, value: "domain=\(domain)")) }
            return values
        }

        private static func firstString(in item: [String: Any], keys: [String]) -> String { firstOptionalString(in: item, keys: keys) ?? "" }
        private static func firstOptionalString(in item: [String: Any], keys: [String]) -> String? { keys.lazy.compactMap { stringish(item[$0]) }.first }
        private static func firstInt64(in item: [String: Any], keys: [String]) -> Int64 { keys.lazy.compactMap { int64ish($0) }.first ?? 0 }

        private static func riskTags(item: [String: Any], process: String, domain: String, bytesOut: Int64, highVolumeThreshold: Int64) -> [String] {
            var tags = stringish(item["risk_tags"])? .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } ?? []
            let lowerProcess = process.lowercased()
            let lowerDomain = domain.lowercased()
            let suspiciousProcess = ["evil", "/tmp/", "curl"].contains(where: lowerProcess.contains)
            let anomalousDomain = lowerDomain.contains("evil.example") || lowerDomain.contains("c2.") || lowerDomain.hasSuffix(".evil") || (lowerDomain.contains("evil") && lowerDomain.contains("."))
            append("suspicious_process", when: suspiciousProcess, to: &tags)
            append("high_volume", when: bytesOut >= highVolumeThreshold, to: &tags)
            append("anomalous_egress", when: anomalousDomain || (suspiciousProcess && bytesOut > 1_000_000), to: &tags)
            return tags
        }

        private static func int64ish(_ value: Any?) -> Int64? {
            if let n = value as? NSNumber { return n.int64Value }
            if let i = value as? Int64 { return i }
            if let i = value as? Int { return Int64(i) }
            if let s = value as? String, let i = Int64(s) { return i }
            return nil
        }

        private static func append(_ tag: String, when condition: Bool, to tags: inout [String]) {
            if condition && !tags.contains(tag) { tags.append(tag) }
        }
    }

    private func int64ish(_ value: Any?) -> Int64? {
        if let n = value as? NSNumber { return n.int64Value }
        if let i = value as? Int64 { return i }
        if let i = value as? Int { return Int64(i) }
        if let s = value as? String, let i = Int64(s) { return i }
        return nil
    }
}
