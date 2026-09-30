import Foundation
import RootstockBlueCore

/// Gatekeeper assessment history from fixture JSON / JSONL exports.
///
/// Paths: `Library/Preferences/com.apple.security.gk.json` or
/// `Library/Logs/Gatekeeper/assessments.jsonl`.
public struct GatekeeperHistoryParser: ArtifactParser {
    private struct AssessmentDetails {
        let path: String
        let result: String
        let policy: String
        let overrideFlag: Bool
        let sourceURL: URL
    }

    public let manifest = PluginManifest(
        id: "GATEKEEPER",
        tier: .tier2,
        description: "Gatekeeper assessment history (allowed/denied paths)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        var seen = PathDeduper()

        appendURLs(root.enumerate(matching: { Self.isHistoryFile($0) }), to: &urls, seen: &seen)
        appendURLs(standardURLs(in: root), to: &urls, seen: &seen)
        return urls.flatMap(parseFile)
    }

    private func standardURLs(in root: ArtifactRoot) -> [URL] {
        [
            "Library/Preferences/com.apple.security.gk.json",
            "Library/Logs/Gatekeeper/assessments.jsonl",
        ].compactMap { root.firstExisting([$0]) }
    }

    private static func isHistoryFile(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        if ["com.apple.security.gk.json", "gk.json", "gatekeeper.json"].contains(name) { return true }
        guard name == "assessments.jsonl" || name == "assessments.json" else { return false }
        return ["Gatekeeper", "gatekeeper", "security"].contains { url.path.contains($0) }
    }

    private func appendURLs(_ candidates: [URL], to urls: inout [URL], seen: inout PathDeduper) {
        for url in candidates where seen.insert(url) {
            ArtifactRoot.appendUnique(&urls, url)
        }
    }

    private func parseFile(_ url: URL) -> [EventEnvelope] {
        url.pathExtension == "jsonl" || url.lastPathComponent.hasSuffix(".jsonl")
            ? parseJSONL(at: url)
            : parseJSON(at: url)
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        let entries = ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["assessments", "items", "history"],
            identityKeys: ["path", "result"]
        )
        return entries.compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let path = assessmentValue(item, keys: ["path", "file", "file_path", "url"])
        let result = assessmentValue(item, keys: ["result", "assessment", "status"])
        let policy = assessmentValue(item, keys: ["policy", "gatekeeper_policy", "rule"])

        guard !path.isEmpty || !result.isEmpty else { return nil }

        let details = AssessmentDetails(
            path: path,
            result: result,
            policy: policy,
            overrideFlag: isOverride(item["override"], result: result, policy: policy),
            sourceURL: sourceURL
        )
        let fields = assessmentFields(item, details: details)
        let entities = assessmentEntities(path: details.path, result: details.result)

        let eventTime = parseDate(item["timestamp"] ?? item["time"] ?? item["assessed_at"])
            ?? fileMTime(sourceURL)

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "gatekeeper.assessment",
                label: "GATEKEEPER"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: eventTime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: entities,
                properties: fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func assessmentValue(_ item: [String: Any], keys: [String]) -> String {
        keys.lazy.compactMap { stringValue(item[$0]) }.first ?? ""
    }

    private func isOverride(_ value: Any?, result: String, policy: String) -> Bool {
        if let bool = value as? Bool { return bool }
        if let number = value as? NSNumber { return number.boolValue }
        if let string = value as? String { return ["true", "1", "yes"].contains(string.lowercased()) }
        let explicitTerms = ["override", "user-approved", "user_override", "user approved"]
        return explicitTerms.contains { result.lowercased().contains($0) }
            || ["user_override", "user-override"].contains { policy.lowercased().contains($0) }
    }

    private func assessmentFields(
        _ item: [String: Any],
        details: AssessmentDetails
    ) -> [String: String] {
        var fields: [String: String] = [
            FieldTaxonomy.filePath: details.path.isEmpty ? ArtifactRoot.pathKey(details.sourceURL) : details.path,
            "gatekeeper.result": details.result,
            "gatekeeper.policy": details.policy,
            "gatekeeper.override": details.overrideFlag ? "true" : "false",
            FieldTaxonomy.eventType: "gatekeeper.assessment",
        ]
        if details.overrideFlag || ["denied", "unsigned", "fail", "reject"].contains(where: details.result.lowercased().contains) {
            fields["gatekeeper.suspicious"] = "true"
        }
        if !details.path.isEmpty { fields["gatekeeper.path"] = details.path }
        if let signer = stringValue(item["signer"]) ?? stringValue(item["signing_id"]) { fields["gatekeeper.signer"] = signer }
        if let team = stringValue(item["team_id"]) ?? stringValue(item["teamId"]) { fields["gatekeeper.team_id"] = team }
        return fields
    }

    private func assessmentEntities(path: String, result: String) -> [EntityID] {
        var entities = [EntityID(kind: .host, value: "gatekeeper|\(result)|\(path)")]
        if !path.isEmpty { entities.append(.file(path: path)) }
        return entities
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
