import Foundation
import RootstockBlueCore

/// Network share / SMB mount dual-use lateral markers (Wave-12 red↔blue pair).
///
/// Honesty: never mounts attacker shares or writes credentials to NetAuth.
public struct NetworkShareMountParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "NETWORKSHAREMOUNT",
        tier: .tier2,
        description: "Network share mount surface markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/network_share_mount.json",
            "Library/Logs/network_share_mount.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "network_share_mount.json" || name == "network_share_mount.jsonl"
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
                fieldPrefix: "share",
                eventType: "network.share_mount",
                identityKind: "network.share_mount",
                identityLabel: "NETWORKSHAREMOUNT",
                entityPrefix: "share",
                defaultRiskTag: "share_surface",
                defaultNotes: "Network share mount markers - never mounts attacker shares or writes credentials to NetAuth"
            )
        )
    }
}
