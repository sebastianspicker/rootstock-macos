import Foundation
import RootstockBlueCore

/// Office / collaboration Most Recently Used (MRU) inventory.
///
/// Covers Microsoft Office, Teams, Slack recent documents/channels markers,
/// deeper than generic Apple RecentDocuments for collab IR narrative.
public struct OfficeMRUParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "OFFICEMRU",
        tier: .tier2,
        description: "Office/Teams/Slack collaboration MRU with risk tags"
    )

    public init() {}

    private struct MRUDetails {
        let app: String
        let path: String
        let title: String
        let channel: String
        let user: String
        let eventTime: Date
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return knownMRUEvents(root, seen: &seen) + discoveredMRUEvents(root, seen: &seen)
    }

    private func knownMRUEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for rel in [
            "Library/Preferences/office_mru.json",
            "Library/Preferences/collab_mru.json",
            "Library/Preferences/msoffice_recent.json",
            "Library/Logs/office_mru.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }
        return events
    }

    private func discoveredMRUEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        root.enumerate(matching: isMRUFile).flatMap { url in
            seen.insert(url) ? parseFile(at: url) : []
        }
    }

    private func isMRUFile(_ url: URL) -> Bool {
        ["office_mru.json", "collab_mru.json", "msoffice_recent.json", "office_mru.jsonl", "File MRU.json"].contains(url.lastPathComponent)
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["items", "recent", "documents"],
            identityKeys: ["path", "app"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = mruDetails(item, sourceURL: sourceURL) else { return nil }
        let risks = mruRisks(item, details: details)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "mru.office",
                label: "OFFICEMRU"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: details.eventTime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: mruEntities(details),
                properties: mruFields(item, details: details, risks: risks),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func mruDetails(_ item: [String: Any], sourceURL: URL) -> MRUDetails? {
        let path = firstString(item, keys: ["path", "url", "file_path"])
        let title = firstString(item, keys: ["title", "name", "document"])
        let channel = firstString(item, keys: ["channel", "workspace"])
        guard !path.isEmpty || !title.isEmpty || !channel.isEmpty else { return nil }
        return MRUDetails(
            app: firstString(item, keys: ["app", "application", "bundle_id"], fallback: "office"), path: path, title: title, channel: channel,
            user: stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? "",
            eventTime: parseDate(item["last_accessed"] ?? item["timestamp"] ?? item["modified"]) ?? Date(timeIntervalSince1970: 0)
        )
    }

    private func firstString(_ item: [String: Any], keys: [String], fallback: String = "") -> String { keys.lazy.compactMap { stringish(item[$0]) }.first ?? fallback }

    private func mruRisks(_ item: [String: Any], details: MRUDetails) -> [String] {
        var risks = stringish(item["risk_tags"])?.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } ?? []
        let path = details.path.lowercased()
        let title = details.title.lowercased()
        if temporaryPath(path) { appendUnique("tmp_path", to: &risks) }
        if suspicious(path: path, title: title) { appendUnique("suspicious_path", to: &risks) }
        if sensitive(path: path, title: title) { appendUnique("sensitive_document", to: &risks) }
        if cloudPath(path) { appendUnique("cloud_document", to: &risks) }
        return risks
    }

    private func suspicious(path: String, title: String) -> Bool { path.contains("evil") || title.contains("evil") || path.contains("payload") || path.contains("implant") }
    private func sensitive(path: String, title: String) -> Bool { path.contains("password") || title.contains("password") || path.contains("secret") || title.contains("credential") || path.contains(".ssh/") || path.hasSuffix(".pem") }
    private func temporaryPath(_ path: String) -> Bool { path.contains("/tmp/") || path.contains("/var/folders/") }
    private func cloudPath(_ path: String) -> Bool { path.contains("sharepoint") || path.contains("onedrive") || path.hasPrefix("https://") }
    private func appendUnique(_ value: String, to values: inout [String]) { if !values.contains(value) { values.append(value) } }

    private func mruFields(_ item: [String: Any], details: MRUDetails, risks: [String]) -> [String: String] {
        var fields: [String: String] = [
            "office.app": details.app, "office.path": details.path, "office.title": String(details.title.prefix(200)), "office.channel": details.channel,
            FieldTaxonomy.eventType: "mru.office",
            FieldTaxonomy.filePath: details.path, FieldTaxonomy.userName: details.user,
        ]
        if let accessed = stringish(item["last_accessed"]) ?? stringish(item["timestamp"]) {
            fields["office.last_accessed"] = accessed
        }
        if !risks.isEmpty {
            fields["office.risk_tags"] = risks.joined(separator: ",")
        }
        return fields
    }

    private func mruEntities(_ details: MRUDetails) -> [EntityID] {
        var refs: [EntityID] = []
        if !details.path.isEmpty { refs.append(.file(path: details.path)) }
        refs.append(EntityID(kind: .host, value: "office|\(details.app)"))
        return refs
    }
}
