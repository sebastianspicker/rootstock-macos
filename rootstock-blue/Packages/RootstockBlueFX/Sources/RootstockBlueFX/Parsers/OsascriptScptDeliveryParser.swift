import Foundation
import RootstockBlueCore

/// Compiled AppleScript / OSA delivery residual markers (Wave-12 red↔blue pair).
///
/// Honesty: never compiles malicious .scpt payloads or executes third-party AppleScripts.
public struct OsascriptScptDeliveryParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "OSASCRIPTSCPT",
        tier: .tier2,
        description: "OSA/scpt delivery surface markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/osascript_scpt_delivery.json",
            "Library/Logs/osascript_scpt_delivery.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "osascript_scpt_delivery.json" || name == "osascript_scpt_delivery.jsonl"
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
                fieldPrefix: "osa",
                eventType: "osascript.scpt",
                identityKind: "osascript.scpt",
                identityLabel: "OSASCRIPTSCPT",
                entityPrefix: "osa",
                defaultRiskTag: "scpt_surface",
                defaultNotes: "OSA/scpt delivery markers - never compiles malicious .scpt payloads or executes third-party AppleScripts"
            )
        )
    }
}
