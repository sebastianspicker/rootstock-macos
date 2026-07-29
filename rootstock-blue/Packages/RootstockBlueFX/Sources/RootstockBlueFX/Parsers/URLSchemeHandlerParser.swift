import Foundation
import RootstockBlueCore

/// URL scheme / document-handler surface markers (Wave-11 red↔blue pair).
///
/// Inventories LaunchServices / CFBundleURLTypes / opener path markers for IR.
/// Honesty: never registers schemes or rewrites handlers.
public struct URLSchemeHandlerParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "URLSCHEMEHANDLER",
        tier: .tier2,
        description: "URL scheme / document-handler delivery surface (path markers)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/url_scheme_handler.json",
            "Library/Logs/url_scheme_handler.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "url_scheme_handler.json" || name == "url_scheme_handler.jsonl"
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
            nestedKeys: ["items", "handlers", "entries", "surfaces"],
            identityKeys: ["handler_path", "scheme", "path", "launch_services_path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = handlerDetails(from: item) else { return nil }
        let fields = handlerFields(item: item, details: details, sourceURL: sourceURL)
        return handlerEnvelope(item: item, sourceURL: sourceURL, details: details, fields: fields)
    }

    private struct HandlerDetails {
        let path: String
        let scheme: String
        let kind: String
        let risk: [String]
    }

    private func handlerDetails(from item: [String: Any]) -> HandlerDetails? {
        let path = stringish(item["handler_path"]) ?? stringish(item["path"]) ?? stringish(item["launch_services_path"]) ?? stringish(item["opener_path"]) ?? ""
        let scheme = stringish(item["scheme"]) ?? stringish(item["url_scheme"]) ?? ""
        guard !path.isEmpty || !scheme.isEmpty else { return nil }
        let kind = (stringish(item["handler_kind"]) ?? stringish(item["kind"]) ?? "launch_services").lowercased()
        return HandlerDetails(path: path, scheme: scheme, kind: kind, risk: handlerRisk(item: item, path: path, scheme: scheme))
    }

    private func handlerRisk(item: [String: Any], path: String, scheme: String) -> [String] {
        var risk = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        if boolish(item["handler_surface"]) == true || !path.isEmpty { appendRisk("handler_surface", to: &risk) }
        if boolish(item["third_party_handler"]) == true { appendRisk("third_party_handler", to: &risk) }
        if !scheme.isEmpty { appendRisk("custom_scheme", to: &risk) }
        return risk
    }

    private func appendRisk(_ tag: String, to risk: inout [String]) {
        if !risk.contains(tag) { risk.append(tag) }
    }

    private func handlerFields(item: [String: Any], details: HandlerDetails, sourceURL: URL) -> [String: String] {
        let user = stringish(item["user"]) ?? inferUser(from: details.path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields = ["url_scheme.handler_path": details.path, "url_scheme.scheme": details.scheme, "url_scheme.handler_kind": details.kind, "url_scheme.notes": stringish(item["notes"]) ?? "URL scheme handler path presence only", FieldTaxonomy.eventType: "url_scheme.handler", FieldTaxonomy.userName: user]
        if !details.risk.isEmpty { fields["url_scheme.risk_tags"] = details.risk.joined(separator: ",") }
        return fields
    }

    private func handlerEnvelope(item: [String: Any], sourceURL: URL, details: HandlerDetails, fields: [String: String]) -> EventEnvelope {
        EventEnvelope(identity: EventEnvelope.Identity(kind: "url_scheme.handler", label: "URLSCHEMEHANDLER"), capture: EventEnvelope.Capture(source: .parser, eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .host, value: "url_scheme|\(details.scheme.isEmpty ? details.path : details.scheme)")], properties: fields, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.88))
    }
}
