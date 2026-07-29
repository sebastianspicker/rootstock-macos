import Foundation
import RootstockBlueCore
import RootstockBlueCase
import RootstockMacFacts

#if canImport(Darwin)
import Darwin
#endif
extension HostIRPosture {
    static func offlineSystemExtensions(root: ArtifactRoot) -> [EventEnvelope] {
        guard !securityPostureListsSystemExtensions(root: root),
              let marker = root.firstExisting(["Library/SystemExtensions", "Library/SystemExtensions/db.plist"]) else { return [] }
        let childEvents = systemExtensionChildEvents(marker: marker)
        return childEvents.isEmpty ? [systemExtensionMarkerEvent(marker)] : childEvents
    }

    private static func securityPostureListsSystemExtensions(root: ArtifactRoot) -> Bool {
        guard let url = root.firstExisting(["Library/Preferences/security_posture.json"]),
              let json = ArtifactIO.jsonDict(contentsOf: url),
              let extensions = json["system_extensions"] as? [Any] else { return false }
        return !extensions.isEmpty
    }

    private static func systemExtensionChildEvents(marker: URL) -> [EventEnvelope] {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: marker.path, isDirectory: &isDirectory),
              isDirectory.boolValue,
              let children = try? FileManager.default.contentsOfDirectory(at: marker, includingPropertiesForKeys: nil) else { return [] }
        return children.filter { !$0.lastPathComponent.hasPrefix(".") }.map(systemExtensionEvent)
    }

    private static func systemExtensionEvent(_ child: URL) -> EventEnvelope {
        let name = child.lastPathComponent
        let path = ArtifactRoot.pathKey(child)
        return EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.system_extension", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "sysext=\(name)"), .file(path: path)],
                properties: ["ir.mode": "offline", "protection.name": "SystemExtension", "protection.enabled": "present", "sysext.name": name, "sysext.state": "present", "protection.marker_path": path, "protection.note": "Offline SystemExtensions path presence; team ID / activation unknown", FieldTaxonomy.filePath: path, FieldTaxonomy.eventType: "ir.posture.system_extension"],
                provenance: path,
                confidence: 0.65
            )
        )
    }

    private static func systemExtensionMarkerEvent(_ marker: URL) -> EventEnvelope {
        let path = ArtifactRoot.pathKey(marker)
        return EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.system_extension", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "sysext=marker"), .file(path: path)],
                properties: ["ir.mode": "offline", "protection.name": "SystemExtension", "protection.enabled": "present", "sysext.name": "unknown", "sysext.state": "marker", "protection.marker_path": path, "protection.note": "SystemExtensions tree present offline", FieldTaxonomy.filePath: path, FieldTaxonomy.eventType: "ir.posture.system_extension"],
                provenance: path,
                confidence: 0.6
            )
        )
    }

    /// Wave-5: emit explicit `ard.all_local_users` when RemoteManagement plist sets ARD_AllLocalUsers.
    static func offlineARDMarkers(root: ArtifactRoot) -> [EventEnvelope] {
        guard let marker = root.firstExisting(["Library/Preferences/com.apple.RemoteManagement.plist", "Library/Preferences/com.apple.RemoteDesktop.plist", "Library/Preferences/ard_inventory.json"]),
              let values = ardMarkerValues(marker),
              values.allLocalUsers else { return [] }
        return [ardMarkerEvent(marker: marker, enabled: values.enabled)]
    }

    private static func ardMarkerValues(_ marker: URL) -> (allLocalUsers: Bool, enabled: Bool?)? {
        if marker.pathExtension == "json", let json = ArtifactIO.jsonDict(contentsOf: marker) {
            let allUsers = boolish(json["ARD_AllLocalUsers"]) ?? boolish(json["ard_all_local_users"]) ?? boolish(json["all_local_users"])
            return allUsers.map { ($0, boolish(json["enabled"]) ?? boolish(json["ard_enabled"])) }
        }
        guard let dictionary = ArtifactIO.plistDict(contentsOf: marker),
              let allUsers = boolish(dictionary["ARD_AllLocalUsers"]) else { return nil }
        let enabled = boolish(dictionary["ScreenSharingEnabled"]) ?? boolish(dictionary["LoadRemoteManagementMenuExtra"]) ?? allUsers
        return (allUsers, enabled)
    }

    private static func ardMarkerEvent(marker: URL, enabled: Bool?) -> EventEnvelope {
        let active = enabled ?? true
        let path = ArtifactRoot.pathKey(marker)
        var fields: [String: String] = [
            "ir.mode": "offline",
            "protection.name": "RemoteManagement",
            "protection.enabled": active ? "true" : "false",
            "remote.service": "ard",
            "remote.enabled": active ? "true" : "false",
            "ard.enabled": active ? "true" : "false",
            "ard.all_local_users": "true",
            "protection.marker_path": path,
            "protection.source": marker.lastPathComponent,
            "protection.note": "Offline ARD_AllLocalUsers=true from Remote Management prefs",
            FieldTaxonomy.eventType: "ir.posture.remote_access",
        ]
        fields[FieldTaxonomy.remoteService] = "ard"
        fields[FieldTaxonomy.remoteEnabled] = active ? "true" : "false"
        return EventEnvelope(
            identity: EventEnvelope.Identity(kind: "ir.posture.remote_access", label: "IRPOSTURE"),
            capture: EventEnvelope.Capture(source: .collect, eventTime: Date(), collectedAt: Date()),
            payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .host, value: "remote=ard|all_local_users")], properties: fields, provenance: path, confidence: 0.9)
        )
    }

    static func offlineRemoteAccessSignals(root: ArtifactRoot) -> [EventEnvelope] {
        let hasPosture = root.exists("Library/Preferences/security_posture.json")
        return [
            remoteManagementMarkerEvent(root: root, hasPosture: hasPosture),
            screenSharingMarkerEvent(root: root, hasPosture: hasPosture),
        ].compactMap { $0 }
    }

    private static func remoteManagementMarkerEvent(root: ArtifactRoot, hasPosture: Bool) -> EventEnvelope? {
        guard let marker = root.firstExisting(["Library/Preferences/com.apple.RemoteManagement.plist", "Library/Preferences/com.apple.RemoteDesktop.plist"]),
              !hasPosture || rootPostureMissingBool(root, key: "remote_management_enabled") else { return nil }
        let enabled = remoteManagementEnabled(marker)
        let path = ArtifactRoot.pathKey(marker)
        return remoteAccessEvent(name: "RemoteManagement", enabled: enabled == "unknown" ? "present" : enabled, mode: "offline", extra: ["protection.marker_path": path, "protection.source": "com.apple.RemoteManagement.plist", "protection.note": "Offline Remote Management prefs present"], rawRef: path, confidence: enabled == "unknown" ? 0.55 : 0.8)
    }

    private static func remoteManagementEnabled(_ marker: URL) -> String {
        guard let dictionary = ArtifactIO.plistDict(contentsOf: marker),
              let enabled = boolish(dictionary["ScreenSharingEnabled"]) ?? boolish(dictionary["ARD_AllLocalUsers"]) else { return "unknown" }
        return enabled ? "true" : "false"
    }

    private static func screenSharingMarkerEvent(root: ArtifactRoot, hasPosture: Bool) -> EventEnvelope? {
        guard let marker = root.firstExisting(["Library/Preferences/com.apple.screensharing.plist", "Library/Preferences/com.apple.screensharing.allowlist.plist", "Library/Preferences/com.apple.screensharing.agent.launchd.plist"]),
              !hasPosture || rootPostureMissingBool(root, key: "screen_sharing_enabled") else { return nil }
        let path = ArtifactRoot.pathKey(marker)
        return remoteAccessEvent(name: "ScreenSharing", enabled: "present", mode: "offline", extra: ["protection.marker_path": path, "protection.source": marker.lastPathComponent, "protection.note": "Offline Screen Sharing prefs marker; live status unknown"], rawRef: path, confidence: 0.55)
    }

}
