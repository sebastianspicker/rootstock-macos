import Foundation
import RootstockBlueCore

/// MDM / configuration profiles - forensic JSON exports, managed preferences, payload plists.
public struct ConfigProfilesParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CONFIGPROFILES",
        tier: .tier2,
        description: "MDM and configuration profile payloads"
    )

    public init() {}

    private struct ProfileDetails {
        let displayName: String
        let identifier: String
        let type: String
        let organization: String
        let path: String
        let sourceURL: URL
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return collectKnownProfiles(root, seen: &seen)
            + collectPayloadProfiles(root, seen: &seen)
            + collectSettingsProfiles(root, seen: &seen)
            + collectManagedPreferences(root, seen: &seen)
    }

    private func collectKnownProfiles(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        if let jsonURL = root.firstExisting([
            "Library/ConfigurationProfiles/profiles.json",
            "var/db/ConfigurationProfiles/profiles.json",
            "private/var/db/ConfigurationProfiles/profiles.json",
        ]) {
            if seen.insert(jsonURL) {
                return parseProfilesJSON(at: jsonURL)
            }
        }
        return []
    }

    private func collectPayloadProfiles(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        root.enumerate(matching: isPayloadPlist).compactMap { url in
            if !seen.insert(url) { return nil }
            return parsePayloadPlist(at: url)
        }
    }

    private func isPayloadPlist(_ url: URL) -> Bool {
        guard url.pathExtension == "plist" else { return false }
        let path = url.path
        return path.contains("ConfigurationProfiles") || path.contains("/payloads/")
            || path.contains("Managed Preferences") || path.contains("ManagedPreferences")
    }

    private func collectSettingsProfiles(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for dirRel in [
            "var/db/ConfigurationProfiles/Settings",
            "private/var/db/ConfigurationProfiles/Settings",
            "Library/ConfigurationProfiles/Settings",
        ] {
            let dir = root.file(dirRel)
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: nil
            ) else { continue }
            for item in items where item.pathExtension == "plist" || item.pathExtension == "json" {
                if !seen.insert(item) { continue }
                if item.pathExtension == "json" {
                    events.append(contentsOf: parseProfilesJSON(at: item))
                } else if let e = parsePayloadPlist(at: item) {
                    events.append(e)
                }
            }
        }
        return events
    }

    private func collectManagedPreferences(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for dirRel in [
            "Library/Managed Preferences",
            "private/var/db/Managed Preferences",
        ] {
            let dir = root.file(dirRel)
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: nil
            ) else { continue }
            for item in items where item.pathExtension == "plist" {
                if !seen.insert(item) { continue }
                if let e = parsePayloadPlist(at: item) {
                    events.append(e)
                } else if let e = parseManagedPreference(at: item) {
                    events.append(e)
                }
            }
        }
        return events
    }

    private func parseProfilesJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries: [[String: Any]]
        if let arr = obj as? [[String: Any]] {
            entries = arr
        } else if let dict = obj as? [String: Any] {
            if let arr = dict["profiles"] as? [[String: Any]] {
                entries = arr
            } else if let arr = dict["PayloadContent"] as? [[String: Any]] {
                entries = arr
            } else {
                entries = [dict]
            }
        } else if let arr = obj as? [Any] {
            entries = arr.compactMap { $0 as? [String: Any] }
        } else {
            return []
        }

        return entries.compactMap { entry in
            makeEvent(profileDetails(entry, sourceURL: url))
        }
    }

    private func parsePayloadPlist(at url: URL) -> EventEnvelope? {
        guard let dict = ArtifactIO.plistDict(contentsOf: url) else { return nil }

        guard hasProfileFields(dict) else { return nil }
        let details = ProfileDetails(
            displayName: stringValue(dict["PayloadDisplayName"]) ?? "",
            identifier: stringValue(dict["PayloadIdentifier"]) ?? url.deletingPathExtension().lastPathComponent,
            type: stringValue(dict["PayloadType"]) ?? "",
            organization: stringValue(dict["PayloadOrganization"]) ?? "",
            path: ArtifactRoot.pathKey(url), sourceURL: url
        )
        guard !details.displayName.isEmpty || !details.identifier.isEmpty || !details.type.isEmpty else { return nil }
        return makeEvent(details)
    }

    private func hasProfileFields(_ dict: [String: Any]) -> Bool {
        ["PayloadDisplayName", "PayloadIdentifier", "PayloadType", "PayloadUUID", "PayloadOrganization"].contains { dict[$0] != nil }
    }

    private func parseManagedPreference(at url: URL) -> EventEnvelope? {
        // Fallback for managed preference domain plists without payload keys.
        let domain = url.deletingPathExtension().lastPathComponent
        guard !domain.isEmpty else { return nil }
        return makeEvent(ProfileDetails(displayName: domain, identifier: domain, type: "managed_preference", organization: "", path: ArtifactRoot.pathKey(url), sourceURL: url))
    }

    private func profileDetails(_ entry: [String: Any], sourceURL: URL) -> ProfileDetails {
        ProfileDetails(
            displayName: firstString(entry, keys: ["PayloadDisplayName", "display_name", "name"]),
            identifier: firstString(entry, keys: ["PayloadIdentifier", "identifier"]),
            type: firstString(entry, keys: ["PayloadType", "type"]),
            organization: firstString(entry, keys: ["PayloadOrganization", "organization"]),
            path: ArtifactRoot.pathKey(sourceURL), sourceURL: sourceURL
        )
    }

    private func firstString(_ entry: [String: Any], keys: [String]) -> String {
        keys.lazy.compactMap { stringValue(entry[$0]) }.first ?? ""
    }

    private func makeEvent(_ details: ProfileDetails) -> EventEnvelope? {
        guard !details.displayName.isEmpty || !details.identifier.isEmpty else { return nil }

        let attrs = try? FileManager.default.attributesOfItem(atPath: details.sourceURL.path)
        let mtime = (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
        let idKey = details.identifier.isEmpty ? details.displayName : details.identifier

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "host.config_profile",
                label: "CONFIGPROFILES"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: mtime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [
                EntityID(kind: .host, value: "profile=\(idKey)"),
                .file(path: details.path),
            ],
                properties: [
                "profile.display_name": details.displayName,
                "profile.identifier": details.identifier,
                "profile.type": details.type,
                "profile.organization": details.organization,
                "profile.path": details.path,
                FieldTaxonomy.filePath: details.path,
                FieldTaxonomy.eventType: "host.config_profile",
            ],
                provenance: details.path,
                confidence: 0.94
            )
        )
    }

}
