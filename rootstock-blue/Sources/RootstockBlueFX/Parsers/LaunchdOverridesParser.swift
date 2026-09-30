import Foundation
import RootstockBlueCore

/// launchd override / disabled job inventory - defense-evasion surface.
///
/// Reads `disabled.plist` and per-user disabled overrides under
/// `/var/db/com.apple.xpc.launchd/`. When security products or IR agents appear
/// as disabled, that is a high-signal blue-team finding (T1562.001).
///
/// Emits normalized `defense.launchd_override` events with team and product
/// heuristics suitable for case custody.
public struct LaunchdOverridesParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "LAUNCHDOVERRIDES",
        tier: .tier1,
        description: "launchd disabled overrides (defense-evasion inventory)"
    )

    public init() {}

    /// Labels that strongly suggest security / IR tooling when disabled.
    private static let securityLabelHints: [String] = [
        "santa", "falcon", "crowdstrike", "sentinel", "jamf", "osquery",
        "xprotect", "mrt", "carbonblack", "elastic", "defender", "lulu",
        "snitch", "blockblock", "oversight", "knockknock", "endpoint",
        "protect", "security", "malware", "avast", "norton", "mcafee",
    ]

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        var events = fixtureJSONEvents(root: root, seen: &seen)
        events.append(contentsOf: standardPlistEvents(root: root, seen: &seen))
        events.append(contentsOf: discoveredOverrideEvents(root: root, seen: &seen))
        return events
    }

    private func fixtureJSONEvents(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        let paths = ["var/db/com.apple.xpc.launchd/disabled.json", "private/var/db/com.apple.xpc.launchd/disabled.json", "Library/Preferences/launchd_disabled.json"]
        return paths.flatMap { path -> [EventEnvelope] in
            guard let url = root.firstExisting([path]), let json = ArtifactIO.jsonObject(contentsOf: url), seen.insert(url) else { return [] }
            return parseJSON(json, rawRef: ArtifactRoot.pathKey(url))
        }
    }

    private func standardPlistEvents(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        ["var/db/com.apple.xpc.launchd/disabled.plist", "private/var/db/com.apple.xpc.launchd/disabled.plist"].flatMap { path -> [EventEnvelope] in
            guard let url = root.firstExisting([path]), seen.insert(url) else { return [] }
            return parseDisabledPlist(at: url)
        }
    }

    private func discoveredOverrideEvents(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        root.enumerate(matching: isOverrideFile).flatMap { url -> [EventEnvelope] in
            guard seen.insert(url) else { return [] }
            if url.pathExtension == "json" { return ArtifactIO.jsonObject(contentsOf: url).map { parseJSON($0, rawRef: ArtifactRoot.pathKey(url)) } ?? [] }
            return parseDisabledPlist(at: url)
        }
    }

    private func isOverrideFile(_ url: URL) -> Bool {
        let path = url.path
        guard path.contains("com.apple.xpc.launchd") || path.contains("/launchd/") else { return false }
        let name = url.lastPathComponent
        return name == "disabled.plist" || name.hasPrefix("disabled.") || name == "overrides.plist"
    }

    private func parseJSON(_ json: Any, rawRef: String) -> [EventEnvelope] {
        if let dictionary = json as? [String: Any] { return dictionaryEvents(dictionary, rawRef: rawRef) }
        if let items = json as? [[String: Any]] { return itemEvents(items, rawRef: rawRef) }
        return []
    }

    private func dictionaryEvents(_ dictionary: [String: Any], rawRef: String) -> [EventEnvelope] {
        if let disabled = dictionary["disabled"] as? [String: Any] { return disabledEvents(disabled, rawRef: rawRef) }
        if let items = dictionary["items"] as? [[String: Any]] { return itemEvents(items, rawRef: rawRef) }
        return disabledEvents(dictionary, rawRef: rawRef)
    }

    private func disabledEvents(_ disabled: [String: Any], rawRef: String) -> [EventEnvelope] {
        disabled.compactMap { label, value in
            guard label != "disabled", label != "items" else { return nil }
            return makeEvent(label: label, disabled: boolish(value) ?? true, path: rawRef, domain: "system")
        }
    }

    private func itemEvents(_ items: [[String: Any]], rawRef: String) -> [EventEnvelope] {
        items.compactMap { item in
            guard let label = stringish(item["label"]) ?? stringish(item["Label"]), !label.isEmpty else { return nil }
            return makeEvent(label: label, disabled: boolish(item["disabled"]) ?? true, path: rawRef, domain: stringish(item["domain"]) ?? "system")
        }
    }

    private func parseDisabledPlist(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url),
              let obj = ArtifactIO.plistObject(from: data)
        else { return [] }
        let pathKey = ArtifactRoot.pathKey(url)
        var events: [EventEnvelope] = []

        if let dict = obj as? [String: Any] {
            for (label, value) in dict {
                let isDisabled = boolish(value) ?? true
                events.append(makeEvent(label: label, disabled: isDisabled, path: pathKey, domain: domainFromPath(url)))
            }
        }
        return events
    }

    private func makeEvent(label: String, disabled: Bool, path: String, domain: String) -> EventEnvelope {
        let lower = label.lowercased()
        let securityRelated = Self.securityLabelHints.contains { lower.contains($0) }
        var fields: [String: String] = [
            "defense.kind": "launchd_override",
            "defense.label": label,
            "defense.disabled": disabled ? "true" : "false",
            "defense.domain": domain,
            "defense.path": path,
            "launchd.label": label,
            "launchd.disabled": disabled ? "true" : "false",
            FieldTaxonomy.filePath: path,
            FieldTaxonomy.eventType: "defense.launchd_override",
            FieldTaxonomy.persistenceLabel: label,
        ]
        if securityRelated {
            fields["defense.security_product_hint"] = "true"
            fields["defense.risk_tags"] = "security_agent_disabled"
        }

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "defense.launchd_override",
                label: "LAUNCHDOVERRIDES"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [
                EntityID(kind: .persistence, value: "launchd_override|\(label)"),
                .file(path: path),
            ],
                properties: fields,
                provenance: path,
                confidence: securityRelated && disabled ? 0.97 : 0.9
            )
        )
    }

    private func domainFromPath(_ url: URL) -> String {
        let name = url.lastPathComponent
        if name.hasPrefix("disabled."), name != "disabled.plist" {
            return "user"
        }
        return "system"
    }
}
