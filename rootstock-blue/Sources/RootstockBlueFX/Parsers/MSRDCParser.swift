import Foundation
import RootstockBlueCore

/// Microsoft Remote Desktop (MSRDC) and related RDP client connection history.
///
/// Surfaces host, user, client app, and last-connected markers for lateral
/// movement / remote-access IR - not credential material from RDP sessions.
public struct MSRDCParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "MSRDC",
        tier: .tier2,
        description: "Remote desktop client connection history (MSRDC/RDP)"
    )

    public init() {}

    private struct ConnectionDetails {
        let host: String
        let rdpUser: String
        let client: String
        let lastConnected: String
        let port: String
        let localUser: String
        let eventTime: Date
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return knownConnectionEvents(root, seen: &seen) + discoveredConnectionEvents(root, seen: &seen)
    }

    private func knownConnectionEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for rel in [
            "Library/Preferences/msrdc_connections.json",
            "Library/Preferences/rdp_connections.json",
            "Library/Preferences/com.microsoft.rdc.macos.json",
            "Library/Logs/msrdc_connections.jsonl",
            "Library/Containers/com.microsoft.rdc.macos/Data/Library/Preferences/connections.json",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }
        return events
    }

    private func discoveredConnectionEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        root.enumerate(matching: isConnectionFile).flatMap { url in
            seen.insert(url) ? parseFile(at: url) : []
        }
    }

    private func isConnectionFile(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        return ["msrdc_connections.json", "rdp_connections.json", "msrdc_connections.jsonl", "com.microsoft.rdc.macos.json"].contains(name)
            || (name == "connections.json" && url.path.lowercased().contains("rdc"))
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["connections", "items", "hosts"],
            identityKeys: ["host", "hostname", "pc_name"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = connectionDetails(item, sourceURL: sourceURL) else { return nil }
        let risks = connectionRisks(item, host: details.host)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "remote.rdp_connection",
                label: "MSRDC"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: details.eventTime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .network, value: "rdp|\(details.host)")],
                properties: connectionFields(item, details: details, risks: risks),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func connectionDetails(_ item: [String: Any], sourceURL: URL) -> ConnectionDetails? {
        let host = firstString(item, keys: ["host", "hostname", "pc_name", "server"])
        guard !host.isEmpty else { return nil }
        return ConnectionDetails(
            host: host, rdpUser: firstString(item, keys: ["user", "username", "friendly_name"]),
            client: firstString(item, keys: ["client", "app"], fallback: "msrdc"),
            lastConnected: firstString(item, keys: ["last_connected", "timestamp", "last_used"]),
            port: firstString(item, keys: ["port"], fallback: "3389"),
            localUser: stringish(item["local_user"]) ?? inferUser(from: sourceURL.path) ?? "",
            eventTime: parseDate(item["last_connected"] ?? item["timestamp"] ?? item["last_used"]) ?? Date(timeIntervalSince1970: 0)
        )
    }

    private func firstString(_ item: [String: Any], keys: [String], fallback: String = "") -> String { keys.lazy.compactMap { stringish(item[$0]) }.first ?? fallback }

    private func connectionRisks(_ item: [String: Any], host: String) -> [String] {
        var risks = stringish(item["risk_tags"])?.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } ?? []
        appendUnique("remote_connection", to: &risks)
        let lower = host.lowercased()
        if suspiciousHost(lower) { appendUnique("suspicious_host", to: &risks) }
        if internalHost(lower) { appendUnique("internal_host", to: &risks) }
        else if lower.contains("."), !lower.hasSuffix(".local") { appendUnique("external_host", to: &risks) }
        return risks
    }

    private func suspiciousHost(_ host: String) -> Bool { host.contains("evil") || host.contains("c2") || host.contains("malware") || host.hasSuffix(".evil") }
    private func internalHost(_ host: String) -> Bool { host.hasPrefix("10.") || host.hasPrefix("192.168.") || host.hasPrefix("172.") }
    private func appendUnique(_ value: String, to items: inout [String]) { if !items.contains(value) { items.append(value) } }

    private func connectionFields(_ item: [String: Any], details: ConnectionDetails, risks: [String]) -> [String: String] {
        var fields: [String: String] = [
            "rdp.host": details.host, "rdp.user": details.rdpUser, "rdp.client": details.client,
            "rdp.port": details.port, "rdp.last_connected": details.lastConnected,
            FieldTaxonomy.eventType: "remote.rdp_connection",
            FieldTaxonomy.userName: details.localUser,
        ]
        if let gateway = stringish(item["gateway"]) {
            fields["rdp.gateway"] = gateway
        }
        if !risks.isEmpty {
            fields["rdp.risk_tags"] = risks.joined(separator: ",")
        }
        return fields
    }
}
