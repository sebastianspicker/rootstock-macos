import Foundation
import RootstockBlueCore

/// DocumentRevisions / Versions.framework markers from inventory JSON and store paths.
///
/// Surfaces prior document versions for recovery and sensitive-document IR context
/// without dumping full document bodies into the case by default.
public struct DocRevisionsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "DOCREVISIONS",
        tier: .tier2,
        description: "DocumentRevisions / Versions inventory (path / version markers)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        appendEvents(from: standardURLs(in: root), to: &events, seen: &seen)
        appendEvents(from: discoveredURLs(in: root), to: &events, seen: &seen)
        appendMarkerEvents(from: root, to: &events, seen: &seen)

        return events
    }

    private func standardURLs(in root: ArtifactRoot) -> [URL] {
        [
            "Library/Preferences/doc_revisions.json",
            "Library/Preferences/document_revisions.json",
            "Library/Logs/doc_revisions.jsonl",
        ].compactMap { root.firstExisting([$0]) }
    }

    private func discoveredURLs(in root: ArtifactRoot) -> [URL] {
        root.enumerate(matching: { Self.isRevisionExport($0) })
    }

    private static func isRevisionExport(_ url: URL) -> Bool {
        ["doc_revisions.json", "document_revisions.json", "doc_revisions.jsonl", "revisions_export.json"]
            .contains(url.lastPathComponent)
    }

    private func appendEvents(from urls: [URL], to events: inout [EventEnvelope], seen: inout PathDeduper) {
        for url in urls where seen.insert(url) {
            events.append(contentsOf: parseFile(at: url))
        }
    }

    private func appendMarkerEvents(from root: ArtifactRoot, to events: inout [EventEnvelope], seen: inout PathDeduper) {
        for url in root.enumerate(matching: { Self.isRevisionMarker($0) }) {
            let key = "docrev-marker:" + ArtifactRoot.pathKey(url)
            if seen.insert(pathKey: key) {
                events.append(markerEvent(for: url))
            }
        }
    }

    private static func isRevisionMarker(_ url: URL) -> Bool {
        let path = url.path
        guard path.contains("DocumentRevisions") || path.contains(".DocumentRevisions") else { return false }
        let name = url.lastPathComponent
        return name == "db-info.txt" || name.hasSuffix(".json") || name.hasSuffix(".marker")
    }

    private func markerEvent(for url: URL) -> EventEnvelope {
        let path = ArtifactRoot.pathKey(url)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "filesystem.doc_revision",
                label: "DOCREVISIONS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [.file(path: path)],
                properties: [
                "docrev.store_path": path,
                "docrev.marker": "true",
                FieldTaxonomy.eventType: "filesystem.doc_revision",
            ],
                provenance: path,
                confidence: 0.7
            )
        )
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else {
            // Non-JSON export markers still get a presence event when path matches
            if url.path.contains("DocumentRevisions") || url.path.contains("doc_revision") {
                return [
                    EventEnvelope(
                        identity: EventEnvelope.Identity(
                            kind: "filesystem.doc_revision",
                            label: "DOCREVISIONS"
                        ),
                        capture: EventEnvelope.Capture(
                            source: .parser,
                            eventTime: Date(timeIntervalSince1970: 0),
                            collectedAt: Date()
                        ),
                        payload: EventEnvelope.Payload(
                            entityRefs: [.file(path: ArtifactRoot.pathKey(url))],
                            properties: [
                            "docrev.store_path": ArtifactRoot.pathKey(url),
                            "docrev.marker": "true",
                            FieldTaxonomy.eventType: "filesystem.doc_revision",
                        ],
                            provenance: ArtifactRoot.pathKey(url),
                            confidence: 0.65
                        )
                    ),
                ]
            }
            return []
        }
        return ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["revisions", "items", "versions"],
            identityKeys: ["path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let path = stringish(item["path"])
            ?? stringish(item["document_path"])
            ?? stringish(item["file"])
            ?? ""
        let version = stringish(item["version"])
            ?? stringish(item["generation"])
            ?? stringish(item["rev"])
            ?? ""
        guard !path.isEmpty || !version.isEmpty else { return nil }

        let risk = riskTags(for: item, path: path)
        let fields = revisionFields(item, path: path, version: version, risk: risk)

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "filesystem.doc_revision",
                label: "DOCREVISIONS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["mtime"] ?? item["modified"]) ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: path.isEmpty ? [] : [.file(path: path)],
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.87
            )
        )
    }

    private func riskTags(for item: [String: Any], path: String) -> [String] {
        var tags = stringish(item["risk_tags"])?.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        } ?? []
        let lower = path.lowercased()
        if ["confidential", "secret", "password", "credential", "ssn", "payroll"].contains(where: lower.contains), !tags.contains("sensitive_document") {
            tags.append("sensitive_document")
        }
        return tags
    }

    private func revisionFields(_ item: [String: Any], path: String, version: String, risk: [String]) -> [String: String] {
        var fields: [String: String] = [
            "docrev.path": path,
            "docrev.version": version,
            FieldTaxonomy.eventType: "filesystem.doc_revision",
        ]
        if let mtime = stringish(item["mtime"]) ?? stringish(item["modified"]) {
            fields["docrev.mtime"] = mtime
        }
        if let gen = stringish(item["gen_store_id"]) ?? stringish(item["store_id"]) {
            fields["docrev.gen_store_id"] = gen
        }
        if !risk.isEmpty {
            fields["docrev.risk_tags"] = risk.joined(separator: ",")
        }
        return fields
    }
}
