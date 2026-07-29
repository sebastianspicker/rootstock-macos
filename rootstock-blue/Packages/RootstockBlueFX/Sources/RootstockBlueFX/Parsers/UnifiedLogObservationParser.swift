import Foundation
import RootstockBlueCore

/// Unified log / logarchive observation depth markers (Wave-12 red↔blue pair).
///
/// Honesty: never dumps private unified-log message bodies or force-collects other users' logarchives.
public struct UnifiedLogObservationParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "UNIFIEDLOGOBS",
        tier: .tier2,
        description: "Unified log observation surface markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/unified_log_observation.json",
            "Library/Logs/unified_log_observation.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "unified_log_observation.json" || name == "unified_log_observation.jsonl"
        }) where seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return ArtifactIO.jsonlDictionaries(contentsOf: url)
                .compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["items", "entries", "surfaces", "paths"],
            identityKeys: ["path", "name", "label", "kind", "tile_path", "share_url"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        SurfaceMarkerEventBuilder.makeEvent(
            from: item,
            sourceURL: sourceURL,
            spec: SurfaceMarkerEventSpec(
                fieldPrefix: "ulog",
                eventType: "unified_log.observation",
                identityKind: "unified_log.observation",
                identityLabel: "UNIFIEDLOGOBS",
                entityPrefix: "ulog",
                defaultRiskTag: "observation_surface",
                defaultNotes: "Unified log observation markers - never dumps private unified-log message bodies or force-collects other users' logarchives"
            )
        )
    }
}
