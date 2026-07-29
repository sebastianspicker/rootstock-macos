import Foundation
import RootstockBlueCore

/// iCloud account / sync **posture markers** - not full content sync dumps.
///
/// Surfaces account presence, Drive enablement, Desktop & Documents sync,
/// and service toggles for IR data-exfil / cloud-sync narrative.
public struct ICloudParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "ICLOUD",
        tier: .tier2,
        description: "iCloud account/sync posture markers (Drive, Desktop&Documents)"
    )

    public init() {}

    private struct AccountDetails {
        let present: Bool
        let driveEnabled: Bool
        let desktopDocuments: Bool
        let photos: Bool
        let keychainSync: Bool
        let findMy: Bool
        let user: String
        let domain: String
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/icloud_account.json",
            "Library/Preferences/com.apple.bird.plist.json",
            "Library/Preferences/icloud_sync.json",
            "Library/Logs/icloud_export.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "icloud_account.json"
                || name == "icloud_sync.json"
                || name == "icloud_export.jsonl"
                || name == "com.apple.bird.plist.json"
        }) where seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        if let account = directAccount(obj, sourceURL: url) {
            return [account]
        }
        return ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["accounts", "items"],
            identityKeys: []
        ).compactMap { makeAccountEvent(from: $0, sourceURL: url) }
    }

    private func directAccount(_ obj: Any, sourceURL: URL) -> EventEnvelope? {
        guard let dict = obj as? [String: Any], hasDirectPosture(dict) else { return nil }
        return makeAccountEvent(from: dict, sourceURL: sourceURL)
    }

    private func hasDirectPosture(_ item: [String: Any]) -> Bool {
        ["account_present", "drive_enabled", "desktop_documents_sync", "services"].contains { item[$0] != nil }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeAccountEvent(from: $0, sourceURL: url) }
    }

    private func makeAccountEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let details = accountDetails(item)
        guard hasPostureSignal(details, item: item) else { return nil }
        let risk = accountRisks(item, details: details)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "cloud.sync_posture",
                label: "ICLOUD"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "icloud|\(details.user.isEmpty ? "account" : details.user)")],
                properties: accountFields(item, details: details, risks: risk),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func accountDetails(_ item: [String: Any]) -> AccountDetails {
        AccountDetails(
            present: boolish(item["account_present"]) ?? true,
            driveEnabled: boolish(item["drive_enabled"]) ?? serviceEnabled(item, name: "iCloudDrive") ?? false,
            desktopDocuments: boolish(item["desktop_documents_sync"]) ?? serviceEnabled(item, name: "DesktopDocuments") ?? false,
            photos: boolish(item["photos_enabled"]) ?? serviceEnabled(item, name: "Photos") ?? false,
            keychainSync: boolish(item["keychain_sync"]) ?? serviceEnabled(item, name: "Keychain") ?? false,
            findMy: boolish(item["find_my"]) ?? serviceEnabled(item, name: "FindMy") ?? false,
            user: stringish(item["signed_in_user"]) ?? stringish(item["user"]) ?? "",
            domain: stringish(item["apple_id_domain"]) ?? stringish(item["account_domain"]) ?? ""
        )
    }

    private func hasPostureSignal(_ details: AccountDetails, item: [String: Any]) -> Bool {
        details.present || details.driveEnabled || details.desktopDocuments || item["services"] != nil || !details.user.isEmpty
    }

    private func accountRisks(_ item: [String: Any], details: AccountDetails) -> [String] {
        var risks = stringish(item["risk_tags"])?
            .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } ?? []
        if details.desktopDocuments, !risks.contains("desktop_documents_sync") { risks.append("desktop_documents_sync") }
        if details.driveEnabled, !risks.contains("drive_enabled") { risks.append("drive_enabled") }
        return risks
    }

    private func accountFields(_ item: [String: Any], details: AccountDetails, risks: [String]) -> [String: String] {
        var fields: [String: String] = [
            "icloud.account_present": boolText(details.present),
            "icloud.drive_enabled": boolText(details.driveEnabled),
            "icloud.desktop_documents_sync": boolText(details.desktopDocuments),
            "icloud.photos_enabled": boolText(details.photos),
            "icloud.keychain_sync": boolText(details.keychainSync),
            "icloud.find_my": boolText(details.findMy),
            "icloud.signed_in_user": details.user,
            "icloud.apple_id_domain": details.domain,
            FieldTaxonomy.eventType: "cloud.sync_posture",
        ]
        appendAppleIDFields(&fields, appleID: stringish(item["apple_id"]))
        if !risks.isEmpty {
            fields["icloud.risk_tags"] = risks.joined(separator: ",")
        }
        if !details.user.isEmpty {
            fields[FieldTaxonomy.userName] = details.user
        }
        return fields
    }

    private func boolText(_ value: Bool) -> String {
        value ? "true" : "false"
    }

    private func appendAppleIDFields(_ fields: inout [String: String], appleID: String?) {
        guard let email = appleID, !email.isEmpty else { return }
        fields["icloud.apple_id_present"] = "true"
        let parts = email.split(separator: "@")
        if parts.count == 2 { fields["icloud.apple_id_domain"] = String(parts[1]) }
    }

    private func serviceEnabled(_ item: [String: Any], name: String) -> Bool? {
        guard let services = item["services"] as? [[String: Any]] else { return nil }
        for svc in services {
            let n = (stringish(svc["name"]) ?? "").lowercased()
            if n == name.lowercased() || n.contains(name.lowercased()) {
                return boolish(svc["enabled"]) ?? true
            }
        }
        return nil
    }
}
