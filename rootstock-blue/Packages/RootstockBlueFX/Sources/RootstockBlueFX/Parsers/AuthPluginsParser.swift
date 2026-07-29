import Foundation
import RootstockBlueCore

/// Authorization plugins (`SecurityAgentPlugins`) - auth-path persistence.
///
/// Inventory of `/Library/Security/SecurityAgentPlugins/*` and JSON inventories.
/// ATT&CK T1556.001 (Modify Authentication Process: Domain Controller Authentication /
/// platform auth plugin loaders). On macOS these load into the auth stack and can
/// intercept credentials at interactive login.
///
/// Significant improvement over directory listing: normalized envelopes, risk tags
/// (unknown vendor, tmp path, unsigned), entity IDs, fixture CI.
/// Does not execute plugins or capture credentials.
public struct AuthPluginsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "AUTHPLUGINS",
        tier: .tier1,
        description: "Authorization / SecurityAgent plugins (auth-path persistence)"
    )

    public init() {}

    private struct PluginDetails {
        let name: String
        let path: String
        let bundleID: String
        let signed: Bool?
        let vendor: String
        let rawRef: String
        let extraRisk: [String]
    }

    private func jsonInventoryURLs(root: ArtifactRoot, seen: inout PathDeduper) -> [(Any, String)] {
        ["Library/Preferences/auth_plugins.json", "Library/Security/authorization_plugins.json", "Library/Preferences/authorization_plugins.json"].compactMap { relativePath in
            guard let url = root.firstExisting([relativePath]),
                  let json = ArtifactIO.jsonObject(contentsOf: url),
                  seen.insert(url)
            else { return nil }
            return (json, ArtifactRoot.pathKey(url))
        }
    }

    private func isPluginFile(_ url: URL) -> Bool {
        let path = url.path
        guard path.contains("/SecurityAgentPlugins/"), !url.hasDirectoryPath else { return false }
        if url.lastPathComponent == "Info.plist" { return true }
        let parent = url.deletingLastPathComponent()
        return parent.path.contains("/SecurityAgentPlugins/")
            && parent.deletingLastPathComponent().lastPathComponent == "SecurityAgentPlugins"
    }

    private func details(forPluginFile url: URL) -> PluginDetails {
        let key = ArtifactRoot.pathKey(url)
        var pluginPath = key
        var pluginName = url.lastPathComponent
        var bundleID = ""
        if pluginName == "Info.plist" {
            let parent = url.deletingLastPathComponent()
            let bundle = parent.lastPathComponent == "Contents" ? parent.deletingLastPathComponent() : parent
            pluginPath = ArtifactRoot.pathKey(bundle)
            pluginName = bundle.lastPathComponent
            if let dict = ArtifactIO.jsonOrPlistDict(contentsOf: url) {
                bundleID = stringish(dict["CFBundleIdentifier"]) ?? stringish(dict["bundle_id"]) ?? ""
            }
        } else {
            let parent = url.deletingLastPathComponent()
            if parent.deletingLastPathComponent().lastPathComponent == "SecurityAgentPlugins" {
                pluginPath = ArtifactRoot.pathKey(parent)
                pluginName = parent.lastPathComponent
            } else if pluginName.hasSuffix(".bundle") {
                pluginName = String(pluginName.dropLast(".bundle".count))
            }
        }
        return PluginDetails(
            name: pluginName,
            path: pluginPath.hasPrefix("/") ? pluginPath : "/Library/Security/SecurityAgentPlugins/\(pluginName)",
            bundleID: bundleID.isEmpty ? pluginName : bundleID,
            signed: nil,
            vendor: "",
            rawRef: key,
            extraRisk: []
        )
    }

    private func inventoryItems(from json: Any) -> [[String: Any]] {
        let items = ArtifactIO.dictionaryEntries(from: json, nestedKeys: ["plugins", "authorization_plugins", "auth_plugins"])
        if !items.isEmpty { return items }
        return (json as? [String: Any]).map { [$0] } ?? []
    }

    private func firstString(_ item: [String: Any], keys: [String]) -> String? {
        keys.lazy.compactMap { stringish(item[$0]) }.first
    }

    private func pluginRisk(_ details: PluginDetails) -> [String] {
        let values = [details.name, details.path, details.bundleID, details.vendor].map { $0.lowercased() }
        let isTemporaryPath = ["/tmp/", "/var/tmp/", "/users/shared/"].contains { values[1].contains($0) }
        let suspiciousName = values[..<3].contains { $0.contains("evil") }
        let vendorNeedsAttention = [values[3] == "unknown", details.vendor.isEmpty && suspiciousName].contains(true)
        let unsignedOrSuspicious = [details.signed == false, suspiciousName].contains(true)
        var risk = details.extraRisk
        if isTemporaryPath { risk.append("tmp_path") }
        if details.signed == false { risk.append("unsigned") }
        if vendorNeedsAttention || unsignedOrSuspicious && values[3] != "apple" { risk.append("unknown_vendor") }
        return Array(Set(risk)).sorted()
    }

    private func pluginFields(_ details: PluginDetails, risk: [String]) -> [String: String] {
        var fields: [String: String] = [
            "persistence.kind": "authorization_plugin",
            "persistence.label": details.name,
            "persistence.path": details.path,
            "auth.plugin_name": details.name,
            "auth.plugin_path": details.path,
            "auth.plugin_bundle_id": details.bundleID,
            "auth.bundle_id": details.bundleID,
            "attack.technique": "T1556.001",
            FieldTaxonomy.filePath: details.path,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if let signed = details.signed { fields["auth.plugin_signed"] = signed ? "true" : "false" }
        if !details.vendor.isEmpty { fields["auth.plugin_vendor"] = details.vendor }
        if !risk.isEmpty {
            let joined = risk.joined(separator: ",")
            fields["persistence.risk_tags"] = joined
            fields["auth.risk_tags"] = joined
        }
        return fields
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        var seenNames = Set<String>()
        var events: [EventEnvelope] = []
        for (json, rawRef) in jsonInventoryURLs(root: root, seen: &seen) {
            let parsed = parseJSONInventory(json, rawRef: rawRef)
            seenNames.formUnion(parsed.compactMap { $0.fields["auth.plugin_name"]?.lowercased() })
            events.append(contentsOf: parsed)
        }
        for url in root.enumerate(matching: isPluginFile) {
            let details = details(forPluginFile: url)
            guard seenNames.insert(details.name.lowercased()).inserted else { continue }
            _ = seen.insert(url)
            events.append(makeEvent(details))
        }
        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        inventoryItems(from: json).compactMap { item in
            let name = firstString(item, keys: ["plugin_name", "name", "label", "bundle_id"]) ?? ""
            let path = firstString(item, keys: ["plugin_path", "path"])
                ?? (name.isEmpty ? "" : "/Library/Security/SecurityAgentPlugins/\(name)")
            guard !name.isEmpty || !path.isEmpty else { return nil }
            let resolvedName = name.isEmpty ? URL(fileURLWithPath: path).lastPathComponent : name
            let risk = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            return makeEvent(PluginDetails(
                name: resolvedName,
                path: path.isEmpty ? "/Library/Security/SecurityAgentPlugins/\(resolvedName)" : path,
                bundleID: firstString(item, keys: ["bundle_id", "CFBundleIdentifier"]) ?? resolvedName,
                signed: boolish(item["signed"]),
                vendor: firstString(item, keys: ["vendor", "team_id"]) ?? "",
                rawRef: rawRef,
                extraRisk: risk
            ))
        }
    }

    private func makeEvent(_ details: PluginDetails) -> EventEnvelope {
        let risk = pluginRisk(details)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "persistence.item",
                label: "AUTHPLUGINS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [
                EntityID(kind: .persistence, value: "authplugin|\(details.name)|\(details.path)"),
                EntityID(kind: .auth, value: "auth_plugin|\(details.bundleID)"),
                .file(path: details.path),
                .file(path: details.rawRef),
            ],
                properties: pluginFields(details, risk: risk),
                provenance: details.rawRef,
                confidence: 0.93
            )
        )
    }
}
