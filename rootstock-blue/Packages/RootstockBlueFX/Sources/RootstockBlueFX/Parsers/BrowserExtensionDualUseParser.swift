import Foundation
import RootstockBlueCore

/// Browser extension dual-use markers (Wave-11 red↔blue pair).
///
/// Complements BROWSEREXTENSIONS inventory with dual-use risk tags for residual pairs.
/// Honesty: never dumps extension storage secrets or cookies.
public struct BrowserExtensionDualUseParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "BROWSEREXTDUALUSE",
        tier: .tier2,
        description: "Browser extension dual-use persistence/collection markers (no secrets)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/browser_extension_dualuse.json",
            "Library/Logs/browser_extension_dualuse.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "browser_extension_dualuse.json" || name == "browser_extension_dualuse.jsonl"
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
            nestedKeys: ["items", "extensions", "entries", "paths"],
            identityKeys: ["extension_path", "path", "browser", "extension_id"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = extensionDetails(from: item) else { return nil }
        let fields = extensionFields(item: item, details: details, sourceURL: sourceURL)
        return extensionEnvelope(item: item, sourceURL: sourceURL, details: details, fields: fields)
    }

    private struct ExtensionDetails {
        let path: String
        let browser: String
        let extensionID: String
        let risk: [String]
    }

    private func extensionDetails(from item: [String: Any]) -> ExtensionDetails? {
        discardExtensionSecrets(in: item)
        let path = stringish(item["extension_path"]) ?? stringish(item["path"]) ?? ""
        let extensionID = stringish(item["extension_id"]) ?? stringish(item["id"]) ?? ""
        guard !path.isEmpty || !extensionID.isEmpty else { return nil }
        let browser = (stringish(item["browser"]) ?? inferBrowser(path)).lowercased()
        return ExtensionDetails(path: path, browser: browser, extensionID: extensionID, risk: extensionRisk(item: item, path: path))
    }

    private func discardExtensionSecrets(in item: [String: Any]) {
        for key in ["password", "cookie", "cookie_value", "secret", "token", "oauth"] { _ = item[key] }
    }

    private func extensionRisk(item: [String: Any], path: String) -> [String] {
        var risk = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.lowercased().contains("password_dump") }
        if boolish(item["broad_permissions"]) == true { appendRisk("broad_permissions", to: &risk) }
        if boolish(item["dual_use_surface"]) == true || !path.isEmpty { appendRisk("dual_use_surface", to: &risk) }
        if boolish(item["fda_adjacent"]) == true { appendRisk("fda_adjacent", to: &risk) }
        return risk
    }

    private func appendRisk(_ tag: String, to risk: inout [String]) {
        if !risk.contains(tag) { risk.append(tag) }
    }

    private func extensionFields(item: [String: Any], details: ExtensionDetails, sourceURL: URL) -> [String: String] {
        let user = stringish(item["user"]) ?? inferUser(from: details.path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields = ["ext_dualuse.browser": details.browser, "ext_dualuse.path": details.path, "ext_dualuse.extension_id": details.extensionID, "ext_dualuse.secrets_exported": "false", "ext_dualuse.notes": stringish(item["notes"]) ?? "Browser extension dual-use path markers - secrets not exported", FieldTaxonomy.eventType: "browser.extension_dualuse", FieldTaxonomy.userName: user]
        if !details.risk.isEmpty { fields["ext_dualuse.risk_tags"] = details.risk.joined(separator: ",") }
        return fields
    }

    private func extensionEnvelope(item: [String: Any], sourceURL: URL, details: ExtensionDetails, fields: [String: String]) -> EventEnvelope {
        EventEnvelope(identity: EventEnvelope.Identity(kind: "browser.extension_dualuse", label: "BROWSEREXTDUALUSE"), capture: EventEnvelope.Capture(source: .parser, eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .host, value: "ext_dualuse|\(details.browser)|\(details.extensionID.isEmpty ? details.path : details.extensionID)")], properties: fields, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.88))
    }

    private func inferBrowser(_ path: String) -> String {
        let p = path.lowercased()
        if p.contains("chrome") { return "chrome" }
        if p.contains("edge") { return "edge" }
        if p.contains("brave") { return "brave" }
        if p.contains("safari") { return "safari" }
        if p.contains("firefox") { return "firefox" }
        return "browser"
    }
}
