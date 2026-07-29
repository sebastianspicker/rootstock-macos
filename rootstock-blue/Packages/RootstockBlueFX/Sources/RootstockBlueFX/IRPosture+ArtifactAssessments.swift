import Foundation
import RootstockBlueCore
import RootstockBlueCase
import RootstockMacFacts

#if canImport(Darwin)
import Darwin
#endif
extension HostIRPosture {
    static func offlineGatekeeperAssessments(root: ArtifactRoot) -> [EventEnvelope] {
        guard !securityPostureListsGatekeeperAssessments(root: root) else { return [] }
        return gatekeeperJSONEvents(root: root) + gatekeeperJSONLEvents(root: root)
    }

    private static func securityPostureListsGatekeeperAssessments(root: ArtifactRoot) -> Bool {
        guard let posture = root.firstExisting(["Library/Preferences/security_posture.json"]),
              let json = ArtifactIO.jsonDict(contentsOf: posture),
              let assessments = json["gatekeeper_assessments"] as? [Any] else { return false }
        return !assessments.isEmpty
    }

    private static func gatekeeperJSONEvents(root: ArtifactRoot) -> [EventEnvelope] {
        guard let url = root.firstExisting(["Library/Preferences/gatekeeper_assessments.json", "Library/Preferences/com.apple.security.assessment.json", "Library/Preferences/com.apple.security.gk.json", "Library/Logs/Gatekeeper/assessments.json"]),
              let object = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        let assessments = gatekeeperAssessmentList(object)
        return assessments.enumerated().compactMap { index, item in
            guard let dictionary = item as? [String: Any] else { return nil }
            return gatekeeperAssessmentEvent(dictionary, index: index, source: url.lastPathComponent, rawRef: ArtifactRoot.pathKey(url))
        }
    }

    private static func gatekeeperAssessmentList(_ object: Any) -> [Any] {
        if let dictionary = object as? [String: Any] { return (dictionary["assessments"] as? [Any]) ?? [] }
        return object as? [Any] ?? []
    }

    private static func gatekeeperJSONLEvents(root: ArtifactRoot) -> [EventEnvelope] {
        guard let url = root.firstExisting(["Library/Logs/Gatekeeper/assessments.jsonl"]),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let rawRef = ArtifactRoot.pathKey(url)
        return text.components(separatedBy: .newlines).enumerated().compactMap { index, line in
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, let data = trimmed.data(using: .utf8),
                  let dictionary = ArtifactIO.jsonDict(from: data) else { return nil }
            return gatekeeperAssessmentEvent(dictionary, index: index, source: "assessments.jsonl", rawRef: rawRef)
        }
    }

    private static func gatekeeperAssessmentEvent(_ dictionary: [String: Any], index: Int, source: String, rawRef: String) -> EventEnvelope {
        let path = stringish(dictionary["path"]) ?? ""
        let result = stringish(dictionary["result"]) ?? "unknown"
        let override = boolish(dictionary["override"]) ?? result.lowercased().contains("override")
        return EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.gatekeeper_assessment", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "gatekeeper=assessment"), path.isEmpty ? EntityID(kind: .host, value: "gk=\(index)") : .file(path: path)],
                properties: ["ir.mode": "offline", "protection.name": "Gatekeeper", "gatekeeper.path": path, "gatekeeper.result": result, "gatekeeper.override": override ? "true" : "false", "protection.source": source, FieldTaxonomy.filePath: path, FieldTaxonomy.eventType: "ir.posture.gatekeeper_assessment"],
                provenance: rawRef,
                confidence: 0.8
            )
        )
    }

    static func rootPostureMissingBool(_ root: ArtifactRoot, key: String) -> Bool {
        guard let url = root.firstExisting(["Library/Preferences/security_posture.json"]),
              let json = ArtifactIO.jsonDict(contentsOf: url)
        else { return true }
        return boolish(json[key]) == nil
    }

    /// Wave-4: Guest / auto-login / kcpassword markers from loginwindow + etc/kcpassword.
    static func offlineAccountAndLoginwindow(root: ArtifactRoot) -> [EventEnvelope] {
        var events = kcpasswordAutoLoginEvents(root: root)
        events.append(contentsOf: loginwindowAccountEvents(root: root))
        return events
    }

    private static func kcpasswordAutoLoginEvents(root: ArtifactRoot) -> [EventEnvelope] {
        guard let marker = root.firstExisting(["etc/kcpassword", "private/etc/kcpassword"]) else { return [] }
        let path = ArtifactRoot.pathKey(marker)
        return [accountPostureEvent(kind: "auto_login", enabled: "true", extra: ["account.kcpassword_present": "true", "account.auto_login_enabled": "true", "protection.marker_path": path, "protection.note": "kcpassword present - auto-login credential material at rest (bytes not exported)"], rawRef: path)]
    }

    private static func loginwindowAccountEvents(root: ArtifactRoot) -> [EventEnvelope] {
        guard let url = root.firstExisting(["Library/Preferences/com.apple.loginwindow.plist", "var/root/Library/Preferences/com.apple.loginwindow.plist"]),
              let dictionary = ArtifactIO.jsonOrPlistDict(contentsOf: url) else { return [] }
        let hasPosture = root.exists("Library/Preferences/security_posture.json")
        let rawRef = ArtifactRoot.pathKey(url)
        return guestAccountEvent(dictionary, root: root, hasPosture: hasPosture, rawRef: rawRef)
            + autoLoginAccountEvent(dictionary, root: root, hasPosture: hasPosture, rawRef: rawRef)
    }

    private static func guestAccountEvent(_ dictionary: [String: Any], root: ArtifactRoot, hasPosture: Bool, rawRef: String) -> [EventEnvelope] {
        guard let guest = boolish(dictionary["GuestEnabled"]),
              !hasPosture || rootPostureMissingBool(root, key: "guest_account_enabled") else { return [] }
        return [accountPostureEvent(kind: "guest", enabled: guest ? "true" : "false", extra: ["account.guest_enabled": guest ? "true" : "false", "protection.source": "com.apple.loginwindow.plist"], rawRef: rawRef)]
    }

    private static func autoLoginAccountEvent(_ dictionary: [String: Any], root: ArtifactRoot, hasPosture: Bool, rawRef: String) -> [EventEnvelope] {
        guard let user = stringish(dictionary["autoLoginUser"]), !user.isEmpty,
              !hasPosture || rootPostureMissingBool(root, key: "auto_login_enabled") else { return [] }
        return [accountPostureEvent(kind: "auto_login", enabled: "true", extra: ["account.auto_login_enabled": "true", "account.auto_login_user": user, "user.name": user, "protection.source": "com.apple.loginwindow.plist"], rawRef: rawRef)]
    }

    /// Wave-4: SMB / File Sharing prefs markers.
    static func offlineFileSharingMarkers(root: ArtifactRoot) -> [EventEnvelope] {
        if root.exists("Library/Preferences/security_posture.json"),
           !rootPostureMissingBool(root, key: "file_sharing_enabled") {
            return []
        }
        let paths = [
            "Library/Preferences/SystemConfiguration/com.apple.smb.server.plist",
            "Library/Preferences/com.apple.AppleFileServer.plist",
        ]
        guard let hit = root.firstExisting(paths) else { return [] }
        var enabled = "present"
        if let dict = ArtifactIO.plistDict(contentsOf: hit) {
            if let b = boolish(dict["Enabled"]) ?? boolish(dict["serverEnabled"]) {
                enabled = b ? "true" : "false"
            }
        }
        return [
            remoteAccessEvent(
                name: "FileSharing",
                enabled: enabled == "present" ? "true" : enabled,
                mode: "offline",
                extra: [
                    "remote.service": "file_sharing",
                    "protection.marker_path": ArtifactRoot.pathKey(hit),
                    "protection.source": hit.lastPathComponent,
                    "protection.note": "Offline File Sharing prefs marker",
                ],
                rawRef: ArtifactRoot.pathKey(hit),
                confidence: enabled == "present" ? 0.6 : 0.85
            ),
        ]
    }

    /// Wave-4: Software Update catalog / auto-check honesty.
    static func offlineSoftwareUpdateMarkers(root: ArtifactRoot) -> [EventEnvelope] {
        guard !securityPostureCoversSoftwareUpdate(root: root),
              let url = root.firstExisting(["Library/Preferences/com.apple.SoftwareUpdate.plist"]),
              let dictionary = ArtifactIO.plistDict(contentsOf: url) else { return [] }
        let rawRef = ArtifactRoot.pathKey(url)
        return automaticUpdateEvents(dictionary, rawRef: rawRef) + softwareUpdateCatalogEvents(dictionary, rawRef: rawRef)
    }

    private static func securityPostureCoversSoftwareUpdate(root: ArtifactRoot) -> Bool {
        guard root.exists("Library/Preferences/security_posture.json"),
              let json = ArtifactIO.jsonDict(contentsOf: root.file("Library/Preferences/security_posture.json")) else { return false }
        return !rootPostureMissingBool(root, key: "software_update_automatic_check") && json["software_update_catalog_url"] != nil
    }

    private static func automaticUpdateEvents(_ dictionary: [String: Any], rawRef: String) -> [EventEnvelope] {
        guard let automatic = boolish(dictionary["AutomaticCheckEnabled"]) else { return [] }
        return [protectionEvent(name: "SoftwareUpdateAuto", enabled: automatic ? "true" : "false", mode: "offline", extra: ["su.automatic_check": automatic ? "true" : "false", "protection.source": "com.apple.SoftwareUpdate.plist"], rawRef: rawRef, confidence: 0.9)]
    }

    private static func softwareUpdateCatalogEvents(_ dictionary: [String: Any], rawRef: String) -> [EventEnvelope] {
        guard let catalog = stringish(dictionary["CatalogURL"]), !catalog.isEmpty else { return [] }
        let appleCatalog = ["swscan.apple.com", "swcdn.apple.com"].contains { catalog.contains($0) }
        return [EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.software_update", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .host, value: "su=catalog")], properties: ["ir.mode": "offline", "protection.name": "SoftwareUpdateCatalog", "protection.enabled": appleCatalog ? "apple_default" : "custom", "su.catalog_url": catalog, "su.catalog_non_apple": appleCatalog ? "false" : "true", "protection.source": "com.apple.SoftwareUpdate.plist", FieldTaxonomy.eventType: "ir.posture.software_update"], provenance: rawRef, confidence: 0.92)
        )]
    }

    /// Wave-4: Lockdown Mode LDMGlobalEnabled from user GlobalPreferences.
    static func offlineLockdownModeMarkers(root: ArtifactRoot) -> [EventEnvelope] {
        guard !securityPostureCoversLockdownMode(root: root) else { return [] }
        return root.enumerate(matching: isGlobalPreferencesFile)
            .compactMap(lockdownModeEvent)
            .prefix(1)
            .map { $0 }
    }

    private static func securityPostureCoversLockdownMode(root: ArtifactRoot) -> Bool {
        guard root.exists("Library/Preferences/security_posture.json"),
              let json = ArtifactIO.jsonDict(contentsOf: root.file("Library/Preferences/security_posture.json")) else { return false }
        return !rootPostureMissingBool(root, key: "lockdown_mode_enabled") || json["lockdown_mode"] != nil
    }

    private static func isGlobalPreferencesFile(_ url: URL) -> Bool {
        [".GlobalPreferences.plist", "GlobalPreferences.plist"].contains(url.lastPathComponent)
    }

    private static func lockdownModeEvent(_ url: URL) -> EventEnvelope? {
        guard let dictionary = ArtifactIO.plistDict(contentsOf: url),
              let value = dictionary["LDMGlobalEnabled"] else { return nil }
        let enabled = lockdownModeState(value)
        let path = ArtifactRoot.pathKey(url)
        return protectionEvent(name: "LockdownMode", enabled: enabled, mode: "offline", extra: ["lockdown.enabled": enabled, "protection.source": path, "protection.note": "LDMGlobalEnabled from GlobalPreferences (1=on, 0=was on/now off)"], rawRef: path, confidence: enabled == "unknown" ? 0.5 : 0.88)
    }

    private static func lockdownModeState(_ value: Any) -> String {
        if let number = value as? NSNumber { return number.intValue == 1 ? "true" : "false" }
        if let enabled = boolish(value) { return enabled ? "true" : "false" }
        return "unknown"
    }

    static func accountPostureEvent(
        kind: String,
        enabled: String,
        extra: [String: String] = [:],
        rawRef: String? = nil
    ) -> EventEnvelope {
        var fields: [String: String] = [
            "ir.mode": "offline",
            "account.kind": kind,
            "account.enabled": enabled,
            "protection.name": kind == "guest" ? "GuestAccount" : "AutoLogin",
            "protection.enabled": enabled,
            FieldTaxonomy.eventType: "ir.posture.account",
        ]
        for (k, v) in extra { fields[k] = v }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "ir.posture.account",
                label: "IRPOSTURE"
            ),
            capture: EventEnvelope.Capture(
                source: .collect,
                eventTime: Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "account=\(kind)")],
                properties: fields,
                provenance: rawRef,
                confidence: 0.88
            )
        )
    }

    static func remoteAccessEvent(
        name: String,
        enabled: String,
        mode: String,
        extra: [String: String] = [:],
        rawRef: String? = nil,
        confidence: Double
    ) -> EventEnvelope {
        var fields: [String: String] = [
            "ir.mode": mode,
            "protection.name": name,
            "protection.enabled": enabled,
            "remote.service": name,
            FieldTaxonomy.eventType: "ir.posture.remote_access",
        ]
        for (k, v) in extra { fields[k] = v }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "ir.posture.remote_access",
                label: "IRPOSTURE"
            ),
            capture: EventEnvelope.Capture(
                source: .collect,
                eventTime: Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "remote=\(name.lowercased())")],
                properties: fields,
                provenance: rawRef,
                confidence: confidence
            )
        )
    }

}
