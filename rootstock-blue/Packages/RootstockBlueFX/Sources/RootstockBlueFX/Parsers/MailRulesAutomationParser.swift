import Foundation
import RootstockBlueCore

/// Mail rules / Apple Mail automation persistence markers (Wave-12 red↔blue pair).
///
/// Honesty: never reads Mail contents or modifies user Mail rules.
public struct MailRulesAutomationParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "MAILRULESAUTO",
        tier: .tier2,
        description: "Mail rules automation surface markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/mail_rules_automation.json",
            "Library/Logs/mail_rules_automation.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "mail_rules_automation.json" || name == "mail_rules_automation.jsonl"
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
                fieldPrefix: "mail_rules",
                eventType: "mail.rules",
                identityKind: "mail.rules",
                identityLabel: "MAILRULESAUTO",
                entityPrefix: "mail_rules",
                defaultRiskTag: "rules_surface",
                defaultNotes: "Mail rules automation markers - never reads Mail contents or modifies user Mail rules"
            )
        )
    }
}
