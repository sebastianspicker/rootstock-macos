import Foundation
import RootstockBlueCore

/// Webloc / Internet Location file delivery markers (Wave-12 red↔blue pair).
///
/// Honesty: never crafts phishing webloc/inetloc payloads or rewrites Internet Location files.
public struct WeblocInetlocParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "WEBLOCINETLOC",
        tier: .tier2,
        description: "Webloc/inetloc delivery surface markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/webloc_inetloc_delivery.json",
            "Library/Logs/webloc_inetloc_delivery.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "webloc_inetloc_delivery.json" || name == "webloc_inetloc_delivery.jsonl"
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
                fieldPrefix: "webloc",
                eventType: "webloc.delivery",
                identityKind: "webloc.delivery",
                identityLabel: "WEBLOCINETLOC",
                entityPrefix: "webloc",
                defaultRiskTag: "delivery_surface",
                defaultNotes: "Webloc/inetloc delivery markers - never crafts phishing webloc/inetloc payloads or rewrites Internet Location files"
            )
        )
    }
}
