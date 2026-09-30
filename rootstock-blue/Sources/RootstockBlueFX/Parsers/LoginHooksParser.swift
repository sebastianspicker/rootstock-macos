import Foundation
import RootstockBlueCore

/// Login / Logout hooks (`com.apple.loginwindow` LoginHook / LogoutHook).
///
/// Deprecated root-context scripts at interactive boundary (ATT&CK T1037.002).
/// Still hunted on fleets with residual malware, old MDM, or red-team tooling.
/// Runtime on latest macOS is version-variable - presence of configuration is the finding.
///
/// Significant improvement over `defaults read`: offline plist + JSON inventory,
/// script existence metadata, risk tags, harden findings, entity IDs, fixture CI.
/// Does not execute hooks or dump secrets.
public struct LoginHooksParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "LOGINHOOKS",
        tier: .tier1,
        description: "loginwindow LoginHook/LogoutHook persistence scripts"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        appendInventoryEvents(from: root, to: &events, seen: &seen)
        appendPlistEvents(from: root, to: &events, seen: &seen)
        appendLoginwindowJSONEvents(from: root, to: &events, seen: &seen)

        return events
    }

    private func appendInventoryEvents(from root: ArtifactRoot, to events: inout [EventEnvelope], seen: inout PathDeduper) {
        let paths = [
            "Library/Preferences/login_hooks.json",
            "Library/Preferences/com.apple.loginwindow.hooks.json",
        ]
        for path in paths {
            guard let url = root.firstExisting([path]),
                  let json = ArtifactIO.jsonObject(contentsOf: url),
                  seen.insert(url)
            else { continue }
            events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
        }
    }

    private func appendPlistEvents(from root: ArtifactRoot, to events: inout [EventEnvelope], seen: inout PathDeduper) {
        let paths = [
            "Library/Preferences/com.apple.loginwindow.plist",
            "var/root/Library/Preferences/com.apple.loginwindow.plist",
            "private/var/root/Library/Preferences/com.apple.loginwindow.plist",
        ]
        for path in paths {
            guard let url = root.firstExisting([path]), seen.insert(url) else { continue }
            events.append(contentsOf: parseLoginwindowPlist(at: url))
        }
    }

    private func appendLoginwindowJSONEvents(from root: ArtifactRoot, to events: inout [EventEnvelope], seen: inout PathDeduper) {
        let paths = [
            "Library/Preferences/com.apple.loginwindow.json",
            "Library/Preferences/loginwindow.json",
        ]
        for path in paths {
            guard let url = root.firstExisting([path]),
                  let json = ArtifactIO.jsonDict(contentsOf: url),
                  seen.insert(url)
            else { continue }
            events.append(contentsOf: eventsFromLoginwindowDict(json, rawRef: ArtifactRoot.pathKey(url)))
        }
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        var items: [[String: Any]] = []
        if let arr = json as? [[String: Any]] {
            items = arr
        } else if let dict = json as? [String: Any] {
            if let hooks = dict["hooks"] as? [[String: Any]] {
                items = hooks
            } else if dict["LoginHook"] != nil || dict["LogoutHook"] != nil {
                return eventsFromLoginwindowDict(dict, rawRef: rawRef)
            } else {
                items = [dict]
            }
        }
        return items.compactMap { inventoryEvent(for: $0, rawRef: rawRef) }
    }

    private func inventoryEvent(for item: [String: Any], rawRef: String) -> EventEnvelope? {
        let hookType = (stringish(item["hook_type"]) ?? stringish(item["type"]) ?? stringish(item["kind"]) ?? "login").lowercased()
        let script = stringish(item["script_path"]) ?? stringish(item["path"]) ?? stringish(item["script"]) ?? ""
        guard !script.isEmpty else { return nil }
        return makeEvent(
            hookType: hookType.contains("out") ? "logout" : "login",
            scriptPath: script,
            scriptExists: boolish(item["script_exists"]).map { $0 ? "true" : "false" },
            rawRef: rawRef
        )
    }

    private func parseLoginwindowPlist(at url: URL) -> [EventEnvelope] {
        // Prefer binary/xml plist; also accept JSON written as .plist in fixtures
        guard let dict = ArtifactIO.jsonOrPlistDict(contentsOf: url) else { return [] }
        return eventsFromLoginwindowDict(dict, rawRef: ArtifactRoot.pathKey(url))
    }

    private func eventsFromLoginwindowDict(_ dict: [String: Any], rawRef: String) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        if let login = stringish(dict["LoginHook"]), !login.isEmpty {
            events.append(makeEvent(hookType: "login", scriptPath: login, scriptExists: nil, rawRef: rawRef))
        }
        if let logout = stringish(dict["LogoutHook"]), !logout.isEmpty {
            events.append(makeEvent(hookType: "logout", scriptPath: logout, scriptExists: nil, rawRef: rawRef))
        }
        // Alternate keys some exports use
        if let login = stringish(dict["login_hook"]), !login.isEmpty {
            events.append(makeEvent(hookType: "login", scriptPath: login, scriptExists: nil, rawRef: rawRef))
        }
        if let logout = stringish(dict["logout_hook"]), !logout.isEmpty {
            events.append(makeEvent(hookType: "logout", scriptPath: logout, scriptExists: nil, rawRef: rawRef))
        }
        return events
    }

    private func makeEvent(
        hookType: String,
        scriptPath: String,
        scriptExists: String?,
        rawRef: String
    ) -> EventEnvelope {
        let kind = hookType == "logout" ? "logout_hook" : "login_hook"
        let risk = riskTags(for: scriptPath)
        let fields = hookFields(kind: kind, hookType: hookType, scriptPath: scriptPath, scriptExists: scriptExists, risk: risk)

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "persistence.item",
                label: "LOGINHOOKS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: hookEntities(hookType: hookType, scriptPath: scriptPath, rawRef: rawRef),
                properties: fields,
                provenance: rawRef,
                confidence: 0.96
            )
        )
    }

    private func riskTags(for scriptPath: String) -> [String] {
        var risk: [String] = []
        let lower = scriptPath.lowercased()
        if ["/tmp/", "/var/tmp/"].contains(where: lower.contains) { risk.append("tmp_path") }
        if lower.contains("/users/shared/") { risk.append("shared_writable") }
        if ["evil", "persist"].contains(where: lower.contains) { risk.append("suspicious_name") }
        return risk
    }

    private func hookFields(kind: String, hookType: String, scriptPath: String, scriptExists: String?, risk: [String]) -> [String: String] {
        var fields: [String: String] = [
            "persistence.kind": kind,
            "persistence.label": "loginwindow.\(hookType)",
            "persistence.command": scriptPath,
            "persistence.path": scriptPath,
            "loginwindow.hook_type": hookType,
            "loginwindow.script_path": scriptPath,
            "attack.technique": "T1037.002",
            FieldTaxonomy.filePath: scriptPath,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if let scriptExists {
            fields["loginwindow.script_exists"] = scriptExists
        }
        if !risk.isEmpty {
            fields["persistence.risk_tags"] = risk.joined(separator: ",")
            fields["loginwindow.risk_tags"] = risk.joined(separator: ",")
        }
        return fields
    }

    private func hookEntities(hookType: String, scriptPath: String, rawRef: String) -> [EntityID] {
        [
            EntityID(kind: .persistence, value: "loginwindow|\(hookType)|\(scriptPath)"),
            .file(path: scriptPath),
            .file(path: rawRef),
        ]
    }
}
