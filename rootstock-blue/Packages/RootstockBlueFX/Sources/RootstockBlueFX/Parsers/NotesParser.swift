import Foundation
import RootstockBlueCore

/// Apple Notes **metadata markers** - titles/folders/mtime only.
///
/// Does not export full note body content (privacy non-goal, same class as
/// NOTIFICATIONS body export refusal).
public struct NotesParser: ArtifactParser {
    private struct NoteDetails {
        let title: String
        let folder: String
        let bodyExported: Bool
        let user: String
        let risk: [String]
    }

    public let manifest = PluginManifest(
        id: "NOTES",
        tier: .tier2,
        description: "Apple Notes metadata markers (no full body dumps)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/notes_metadata.json",
            "Library/Preferences/notes_export.json",
            "Library/Logs/notes_metadata.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "notes_metadata.json"
                || name == "notes_export.json"
                || name == "notes_metadata.jsonl"
        }) where seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["notes", "items"],
            identityKeys: ["title", "title_marker"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let titleMarker = noteValue(item, keys: ["title_marker", "title", "name"])
        let folder = noteValue(item, keys: ["folder", "account"])
        let cappedTitle = String(titleMarker.prefix(120))

        guard !cappedTitle.isEmpty || !folder.isEmpty else { return nil }

        let risk = riskTags(for: item, title: cappedTitle)

        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""
        let bodyExported = boolish(item["body_exported"]) == true
        let details = NoteDetails(title: cappedTitle, folder: folder, bodyExported: bodyExported, user: user, risk: risk)
        let fields = noteFields(item, details: details)

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "notes.metadata",
                label: "NOTES"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["modified_at"] ?? item["timestamp"] ?? item["created_at"])
                ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [
                EntityID(kind: .host, value: "notes|\(cappedTitle.prefix(40))"),
            ],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }

    private func noteValue(_ item: [String: Any], keys: [String]) -> String {
        keys.lazy.compactMap { stringish(item[$0]) }.first ?? ""
    }

    private func riskTags(for item: [String: Any], title: String) -> [String] {
        var tags = stringish(item["risk_tags"])?.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        } ?? []
        let lower = title.lowercased()
        append("sensitive_title", when: ["password", "credential", "secret", "api key", "private key", "ssn", "wifi password"].contains { lower.contains($0) }, to: &tags)
        append("suspicious_title", when: ["evil", "c2", "implant"].contains { lower.contains($0) }, to: &tags)
        return tags
    }

    private func append(_ tag: String, when condition: Bool, to tags: inout [String]) {
        if condition, !tags.contains(tag) {
            tags.append(tag)
        }
    }

    private func noteFields(
        _ item: [String: Any],
        details: NoteDetails
    ) -> [String: String] {
        var fields: [String: String] = [
            "notes.title_marker": details.title,
            "notes.folder": details.folder,
            "notes.body_exported": details.bodyExported ? "true" : "false",
            FieldTaxonomy.eventType: "notes.metadata",
            FieldTaxonomy.userName: details.user,
        ]
        if let modified = stringish(item["modified_at"]) ?? stringish(item["timestamp"]) { fields["notes.modified_at"] = modified }
        if let created = stringish(item["created_at"]) { fields["notes.created_at"] = created }
        if let noteID = stringish(item["note_id"]) ?? stringish(item["id"]) { fields["notes.note_id_marker"] = String(noteID.prefix(40)) }
        if !details.risk.isEmpty { fields["notes.risk_tags"] = details.risk.joined(separator: ",") }
        return fields
    }
}
