import Foundation
import RootstockBlueCore

/// Apple Remote Desktop / Remote Management posture from prefs + inventory.
///
/// Parses `com.apple.RemoteManagement.plist` (including `ARD_AllLocalUsers`),
/// JSON inventories, and VNC allow flags for remote-access IR posture.
/// Complements IRPosture offline remote-access signals with richer ARD fields.
public struct ARDParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "ARD",
        tier: .tier1,
        description: "Apple Remote Desktop / Remote Management posture and allow lists"
    )

    public init() {}

    private struct Observation {
        let enabled: Bool?
        let allLocalUsers: Bool?
        let allowVNC: Bool?
        let users: [String]
        let rawRef: String
        let sourceNote: String
    }

    private func collectJSONInventories(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for relativePath in ["Library/Preferences/ard_inventory.json", "Library/Preferences/com.apple.RemoteManagement.json"] {
            guard let url = root.firstExisting([relativePath]) else { continue }
            guard let json = ArtifactIO.jsonObject(contentsOf: url), seen.insert(url) else { continue }
            events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
        }
        return events
    }

    private func collectKnownManagementSources(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for relativePath in ["Library/Preferences/com.apple.RemoteManagement.plist", "Library/Preferences/com.apple.RemoteDesktop.plist", "var/db/RemoteManagement.launchd"] {
            guard let url = root.firstExisting([relativePath]), seen.insert(url) else { continue }
            if relativePath.hasSuffix(".plist") {
                events.append(contentsOf: parseRemoteManagementPlist(at: url))
            } else {
                events.append(makeEvent(Observation(
                    enabled: true,
                    allLocalUsers: nil,
                    allowVNC: nil,
                    users: [],
                    rawRef: ArtifactRoot.pathKey(url),
                    sourceNote: "marker"
                )))
            }
        }
        return events
    }

    private func collectDiscoveredSources(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        let names = ["ard_inventory.json", "com.apple.RemoteManagement.json", "com.apple.RemoteManagement.plist"]
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: { names.contains($0.lastPathComponent) }) {
            guard seen.insert(url) else { continue }
            if url.pathExtension == "plist" {
                events.append(contentsOf: parseRemoteManagementPlist(at: url))
            } else if let json = ArtifactIO.jsonObject(contentsOf: url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }
        return events
    }

    private func firstBool(in dictionary: [String: Any], keys: [String]) -> Bool? {
        keys.lazy.compactMap { boolish(dictionary[$0]) }.first
    }

    private func inventoryUsers(in dictionary: [String: Any]) -> [String] {
        ["users", "ARD_Users", "allow_list", "allowlist"].flatMap { stringArray(dictionary[$0]) }
    }

    private func hasARDEvidence(
        enabled: Bool?,
        allLocalUsers: Bool?,
        allowVNC: Bool?,
        users: [String],
        dictionary: [String: Any]
    ) -> Bool {
        let booleans = [enabled, allLocalUsers, allowVNC]
        return booleans.contains { $0 != nil }
            || !users.isEmpty
            || dictionary["ARD_AllLocalUsers"] != nil
            || stringish(dictionary["remote.service"])?.lowercased() == "ard"
    }

    private func flag(_ value: Bool) -> String {
        value ? "true" : "false"
    }

    private func baseARDFields(enabled: Bool, sourceNote: String) -> [String: String] {
        [
            "ard.enabled": flag(enabled),
            FieldTaxonomy.remoteService: "ard",
            FieldTaxonomy.remoteEnabled: flag(enabled),
            "protection.name": "RemoteManagement",
            "protection.enabled": flag(enabled),
            "ard.source": sourceNote,
            FieldTaxonomy.eventType: "remote.management",
            "ir.posture.remote_access": flag(enabled),
        ]
    }

    private func addARDDetails(
        to fields: inout [String: String],
        allLocalUsers: Bool?,
        allowVNC: Bool?,
        users: [String]
    ) {
        if let allLocalUsers { fields["ard.all_local_users"] = flag(allLocalUsers) }
        if let allowVNC { fields["ard.allow_vnc"] = flag(allowVNC) }
        if !users.isEmpty { fields["ard.users"] = users.joined(separator: ",") }
        if allLocalUsers == true {
            fields["ard.risk_tags"] = "all_local_users"
            fields["remote.risk_tags"] = "all_local_users"
        }
    }

    private func ardFields(
        enabled: Bool,
        allLocalUsers: Bool?,
        allowVNC: Bool?,
        users: [String],
        sourceNote: String
    ) -> [String: String] {
        var fields = baseARDFields(enabled: enabled, sourceNote: sourceNote)
        addARDDetails(to: &fields, allLocalUsers: allLocalUsers, allowVNC: allowVNC, users: users)
        return fields
    }

    private func ardEntities(enabled: Bool, allLocalUsers: Bool?, rawRef: String) -> [EntityID] {
        let access = allLocalUsers.map { $0 ? "all" : "restricted" } ?? "unknown"
        return [
            EntityID(kind: .host, value: "remote=ard"),
            EntityID(kind: .host, value: "ard|\(enabled)|\(access)"),
            .file(path: rawRef),
        ]
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return collectJSONInventories(root: root, seen: &seen)
            + collectKnownManagementSources(root: root, seen: &seen)
            + collectDiscoveredSources(root: root, seen: &seen)
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        // Single posture object or list of configs
        if let dict = json as? [String: Any] {
            // Nested configs array
            if let configs = dict["configs"] as? [[String: Any]] {
                return configs.compactMap { dictEvent($0, rawRef: rawRef) }
            }
            if let items = dict["items"] as? [[String: Any]] {
                return items.compactMap { dictEvent($0, rawRef: rawRef) }
            }
            if let ard = dict["ard"] as? [String: Any] {
                return [dictEvent(ard, rawRef: rawRef)].compactMap { $0 }
            }
            if let event = dictEvent(dict, rawRef: rawRef) {
                return [event]
            }
        }
        if let arr = json as? [[String: Any]] {
            return arr.compactMap { dictEvent($0, rawRef: rawRef) }
        }
        return []
    }

    private func dictEvent(_ dict: [String: Any], rawRef: String) -> EventEnvelope? {
        let enabled = firstBool(in: dict, keys: ["enabled", "ard.enabled", "RemoteManagementEnabled", "ScreenSharingEnabled"])
        let allLocal = firstBool(in: dict, keys: ["all_local_users", "ARD_AllLocalUsers", "ard.all_local_users"])
        let allowVNC = firstBool(in: dict, keys: ["allow_vnc", "VNCEnabled", "ard.allow_vnc", "AllowVNC"])
        let users = inventoryUsers(in: dict)
        guard hasARDEvidence(enabled: enabled, allLocalUsers: allLocal, allowVNC: allowVNC, users: users, dictionary: dict) else {
            return nil
        }
        return makeEvent(Observation(
            enabled: enabled ?? true,
            allLocalUsers: allLocal,
            allowVNC: allowVNC,
            users: users,
            rawRef: rawRef,
            sourceNote: "inventory"
        ))
    }

    private func parseRemoteManagementPlist(at url: URL) -> [EventEnvelope] {
        guard let dict = ArtifactIO.jsonOrPlistDict(contentsOf: url) else { return [] }
        let allLocal = boolish(dict["ARD_AllLocalUsers"])
        let screenSharing = boolish(dict["ScreenSharingEnabled"])
        let allowVNC = boolish(dict["VNCEnabled"]) ?? boolish(dict["LoadRemoteManagementMenuExtra"])
        let users = stringArray(dict["ARD_Users"]) + stringArray(dict["AllowList"])
        return [makeEvent(Observation(
            enabled: screenSharing ?? allLocal ?? (allowVNC == true ? true : nil) ?? true,
            allLocalUsers: allLocal,
            allowVNC: allowVNC ?? screenSharing,
            users: users,
            rawRef: ArtifactRoot.pathKey(url),
            sourceNote: "plist"
        ))]
    }

    private func makeEvent(_ observation: Observation) -> EventEnvelope {
        let enabled = observation.enabled ?? false
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "remote.management",
                label: "ARD"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: ardEntities(enabled: enabled, allLocalUsers: observation.allLocalUsers, rawRef: observation.rawRef),
                properties: ardFields(
                enabled: enabled,
                allLocalUsers: observation.allLocalUsers,
                allowVNC: observation.allowVNC,
                users: observation.users,
                sourceNote: observation.sourceNote
            ),
                provenance: observation.rawRef,
                confidence: 0.94
            )
        )
    }
}
