import Foundation
import RootstockBlueCore

/// Launchd override depth markers (Wave-11 red↔blue pair).
///
/// Distinct from LAUNCHDOVERRIDES stock parser: focuses on **security-product disable depth**.
/// Honesty: never disables jobs or writes overrides.
public struct LaunchdOverrideDepthParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "LAUNCHDOVERRIDEDEPTH",
        tier: .tier2,
        description: "Launchd override depth / security-disable surface markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/launchd_override_depth.json",
            "Library/Logs/launchd_override_depth.jsonl",
            "private/var/db/com.apple.xpc.launchd/disabled_inventory.json",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "launchd_override_depth.json"
                || name == "launchd_override_depth.jsonl"
                || name == "disabled_inventory.json"
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
            nestedKeys: ["items", "overrides", "entries", "disabled"],
            identityKeys: ["label", "override_path", "path", "security_product"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = overrideDetails(from: item) else { return nil }
        let fields = overrideFields(item: item, details: details, sourceURL: sourceURL)
        return overrideEnvelope(item: item, sourceURL: sourceURL, details: details, fields: fields)
    }

    private struct OverrideDetails {
        let label: String
        let path: String
        let securityHint: Bool
        let risk: [String]
    }

    private func overrideDetails(from item: [String: Any]) -> OverrideDetails? {
        let label = stringish(item["label"]) ?? stringish(item["job_label"]) ?? stringish(item["security_product"]) ?? ""
        let path = stringish(item["override_path"]) ?? stringish(item["path"]) ?? ""
        guard !label.isEmpty || !path.isEmpty else { return nil }
        let securityHint = isSecurityProduct(item: item, label: label)
        return OverrideDetails(label: label, path: path, securityHint: securityHint, risk: overrideRisk(item: item, path: path, securityHint: securityHint))
    }

    private func isSecurityProduct(item: [String: Any], label: String) -> Bool {
        boolish(item["security_product_hint"]) == true || ["santa", "falcon", "osquery", "wdav", "jamf"].contains { label.localizedCaseInsensitiveContains($0) }
    }

    private func overrideRisk(item: [String: Any], path: String, securityHint: Bool) -> [String] {
        var risk = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        if securityHint { appendRisk("security_product_disabled", to: &risk) }
        if boolish(item["override_surface"]) == true || !path.isEmpty { appendRisk("override_depth", to: &risk) }
        return risk
    }

    private func appendRisk(_ tag: String, to risk: inout [String]) {
        if !risk.contains(tag) { risk.append(tag) }
    }

    private func overrideFields(item: [String: Any], details: OverrideDetails, sourceURL: URL) -> [String: String] {
        let user = stringish(item["user"]) ?? inferUser(from: details.path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields = ["launchd_depth.label": details.label, "launchd_depth.override_path": details.path, "launchd_depth.security_product_hint": details.securityHint ? "true" : "false", "launchd_depth.notes": stringish(item["notes"]) ?? "Launchd override depth marker - never disables jobs", FieldTaxonomy.eventType: "launchd.override_depth", FieldTaxonomy.userName: user]
        if !details.risk.isEmpty { fields["launchd_depth.risk_tags"] = details.risk.joined(separator: ",") }
        return fields
    }

    private func overrideEnvelope(item: [String: Any], sourceURL: URL, details: OverrideDetails, fields: [String: String]) -> EventEnvelope {
        EventEnvelope(identity: EventEnvelope.Identity(kind: "launchd.override_depth", label: "LAUNCHDOVERRIDEDEPTH"), capture: EventEnvelope.Capture(source: .parser, eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .persistence, value: "launchd_depth|\(details.label.isEmpty ? details.path : details.label)")], properties: fields, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.9))
    }
}
