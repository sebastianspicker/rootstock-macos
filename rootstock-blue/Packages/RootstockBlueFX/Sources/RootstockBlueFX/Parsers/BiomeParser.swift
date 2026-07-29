import Foundation
import RootstockBlueCore

/// Apple Biome / pattern-of-life streams (fixture-friendly JSON/JSONL).
///
/// Real Biome stores are protobuf-heavy; collectors often export JSONL under
/// `Users/*/Library/Biome/streams/**`. This parser also accepts a simplified
/// `streams.json` inventory listing.
public struct BiomeParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "BIOME",
        tier: .tier2,
        description: "Biome / pattern-of-life stream events (app_launch, screen_time, media_playback)"
    )

    public init() {}

    private struct BiomeDetails {
        let stream: String
        let value: String
        let timestamp: Date?
        let user: String?
        let sourceURL: URL
        let extra: [String: Any]
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        let urls = discoveredBiomeURLs(root) + knownBiomeURLs(root)
        return urls.flatMap(parseBiomeFile)
    }

    private func discoveredBiomeURLs(_ root: ArtifactRoot) -> [URL] {
        var urls: [URL] = []
        var seen = PathDeduper()
        for found in root.enumerate(matching: isBiomeFile) {
            if !seen.insert(found) { continue }
            ArtifactRoot.appendUnique(&urls, found)
        }
        return urls
    }

    private func isBiomeFile(_ url: URL) -> Bool {
        guard url.path.contains("/Biome") || url.path.contains("/Library/Biome") else { return false }
        let name = url.lastPathComponent
        return name == "streams.json" || name.hasSuffix(".jsonl") || name.hasSuffix(".json")
    }

    private func knownBiomeURLs(_ root: ArtifactRoot) -> [URL] {
        var urls: [URL] = []
        var seen = PathDeduper()
        for rel in [
            "Users/alice/Library/Biome/streams.json",
            "Users/alice/Library/Biome/streams/app_launch.jsonl",
            "Users/alice/Library/Biome/streams/screen_time.jsonl",
            "Users/alice/Library/Biome/streams/media_playback.jsonl",
        ] {
            if let u = root.firstExisting([rel]) {
                if seen.insert(u) {
                    ArtifactRoot.appendUnique(&urls, u)
                }
            }
        }
        return urls
    }

    private func parseBiomeFile(_ url: URL) -> [EventEnvelope] {
        if url.lastPathComponent == "streams.json" { return parseStreamsInventory(at: url) }
        if url.pathExtension == "jsonl" || url.lastPathComponent.hasSuffix(".jsonl") { return parseJSONL(at: url) }
        return url.pathExtension == "json" ? parseJSONArrayOrObject(at: url) : []
    }

    // MARK: - streams.json inventory

    private func parseStreamsInventory(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let items = streamInventoryItems(obj)
        let user = inferUser(from: url)
        return items.compactMap { item in
            makeEvent(inventoryDetails(item, user: user, sourceURL: url))
        }
    }

    // MARK: - JSONL stream files

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        let user = inferUser(from: url)
        let streamHint = streamNameFromPath(url)
        return ArtifactIO.jsonlDictionaries(contentsOf: url).compactMap { obj in
            makeEvent(jsonlDetails(obj, streamHint: streamHint, user: user, sourceURL: url))
        }
    }

    // MARK: - JSON array of events (non-inventory)

    private func parseJSONArrayOrObject(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries = eventEntries(obj)
        let user = inferUser(from: url)
        let streamHint = streamNameFromPath(url)
        return entries.compactMap { item in
            makeEvent(eventDetails(item, streamHint: streamHint, user: user, sourceURL: url))
        }
    }

    // MARK: - event builder

    private func makeEvent(_ details: BiomeDetails) -> EventEnvelope? {
        guard !details.stream.isEmpty || !details.value.isEmpty else { return nil }
        let eventType = biomeEventType(details.stream)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: eventType,
                label: "BIOME"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: details.timestamp ?? fileMTime(details.sourceURL),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: biomeEntities(details),
                properties: biomeFields(details, eventType: eventType),
                provenance: ArtifactRoot.pathKey(details.sourceURL),
                confidence: 0.88
            )
        )
    }

    private func biomeEventType(_ stream: String) -> String {
        let lower = stream.lowercased()
        if lower.contains("app_launch") || lower.contains("app/launch") || lower.contains("applaunch") { return "pol.biome.app_launch" }
        if lower.contains("screen_time") || lower.contains("screentime") { return "pol.biome.screen_time" }
        return (lower.contains("media") || lower.contains("playback")) ? "pol.biome.media_playback" : "pol.biome.event"
    }

    private func biomeFields(_ details: BiomeDetails, eventType: String) -> [String: String] {
        var fields: [String: String] = [
            "pol.stream": details.stream,
            "pol.value": details.value,
            "pol.source": "biome",
            FieldTaxonomy.eventType: eventType,
            FieldTaxonomy.filePath: ArtifactRoot.pathKey(details.sourceURL),
        ]
        if let user = details.user, !user.isEmpty {
            fields[FieldTaxonomy.userName] = user
        }
        if let duration = stringValue(details.extra["duration"]) ?? stringValue(details.extra["duration_seconds"]) {
            fields["pol.duration_seconds"] = duration
        }
        if let bundle = stringValue(details.extra["bundle_id"]) ?? stringValue(details.extra["bundleId"]) {
            fields["pol.bundle_id"] = bundle
        }
        return fields
    }

    private func biomeEntities(_ details: BiomeDetails) -> [EntityID] {
        var entities: [EntityID] = [
            EntityID(kind: .host, value: "biome|\(details.stream)"),
        ]
        if !details.value.isEmpty {
            entities.append(EntityID(kind: .persistence, value: "biome|\(details.value)"))
        }
        if let user = details.user, !user.isEmpty {
            entities.append(.user(name: user))
        }
        return entities
    }

    // MARK: - helpers

    private func streamInventoryItems(_ obj: Any) -> [[String: Any]] {
        if let items = obj as? [[String: Any]] { return items }
        let dict = obj as? [String: Any]
        return (dict?["streams"] as? [[String: Any]]) ?? (dict?["items"] as? [[String: Any]]) ?? []
    }

    private func eventEntries(_ obj: Any) -> [[String: Any]] {
        if let entries = obj as? [[String: Any]] { return entries }
        guard let dict = obj as? [String: Any] else { return [] }
        if let entries = dict["events"] as? [[String: Any]] { return entries }
        if let entries = dict["items"] as? [[String: Any]] { return entries }
        return (dict["stream"] != nil || dict["value"] != nil || dict["app"] != nil) ? [dict] : []
    }

    private func inventoryDetails(_ item: [String: Any], user: String?, sourceURL: URL) -> BiomeDetails {
        BiomeDetails(stream: firstString(item, keys: ["stream", "name", "id"], fallback: "unknown"), value: firstString(item, keys: ["value", "app", "bundle_id", "title"]), timestamp: parseDate(item["timestamp"] ?? item["time"] ?? item["start"]), user: user, sourceURL: sourceURL, extra: item)
    }

    private func jsonlDetails(_ item: [String: Any], streamHint: String, user: String?, sourceURL: URL) -> BiomeDetails {
        let stream = firstString(item, keys: ["stream", "stream_name"], fallback: streamHint)
        return BiomeDetails(stream: stream.isEmpty ? "biome.unknown" : stream, value: firstString(item, keys: ["value", "app", "bundle_id", "title", "media_title"]), timestamp: parseDate(item["timestamp"] ?? item["time"] ?? item["start"] ?? item["event_time"]), user: user, sourceURL: sourceURL, extra: item)
    }

    private func eventDetails(_ item: [String: Any], streamHint: String, user: String?, sourceURL: URL) -> BiomeDetails {
        BiomeDetails(stream: firstString(item, keys: ["stream"], fallback: streamHint), value: firstString(item, keys: ["value", "app", "bundle_id"]), timestamp: parseDate(item["timestamp"] ?? item["time"] ?? item["start"]), user: user, sourceURL: sourceURL, extra: item)
    }

    private func firstString(_ item: [String: Any], keys: [String], fallback: String = "") -> String {
        keys.lazy.compactMap { stringValue(item[$0]) }.first ?? fallback
    }

    private func streamNameFromPath(_ url: URL) -> String {
        let name = url.deletingPathExtension().lastPathComponent
        if name == "streams" || name.isEmpty { return "biome.stream" }
        return name
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
