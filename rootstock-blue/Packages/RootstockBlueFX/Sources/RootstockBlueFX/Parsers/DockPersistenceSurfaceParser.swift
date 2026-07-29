import Foundation
import RootstockBlueCore

/// Dock persistent apps / recent items dual-use markers (Wave-12 red↔blue pair).
///
/// Honesty: never modifies Dock.plist or plants malicious Dock entries.
public struct DockPersistenceSurfaceParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "DOCKPERSIST",
        tier: .tier2,
        description: "Dock persistence dual-use surface markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/dock_persistence_surface.json",
            "Library/Logs/dock_persistence_surface.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "dock_persistence_surface.json" || name == "dock_persistence_surface.jsonl"
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
                fieldPrefix: "dock",
                eventType: "dock.persistence",
                identityKind: "dock.persistence",
                identityLabel: "DOCKPERSIST",
                entityPrefix: "dock",
                defaultRiskTag: "dock_surface",
                defaultNotes: "Dock persistence dual-use markers - never modifies Dock.plist or plants malicious Dock entries"
            )
        )
    }
}
