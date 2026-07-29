import Foundation
import RootstockBlueCore

/// iTunes / Finder iDevice backup markers - device inventory + encryption posture.
///
/// Surfaces backup presence, last backup time, encrypted flag, and device name
/// markers for dual-device evidence IR. Does not dump backup payload contents.
public struct IDeviceBackupParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "IDEVICEBACKUP",
        tier: .tier2,
        description: "iDevice backup markers (device/encrypt posture, not payload dump)"
    )

    public init() {}

    private struct BackupDetails {
        let deviceName: String
        let encrypted: Bool?
        let lastBackup: String
        let product: String
        let iosVersion: String
        let udidMarker: String
        let path: String
        let user: String
        let eventTime: Date
    }

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        return knownBackupEvents(root, seen: &seen) + discoveredBackupEvents(root, seen: &seen)
    }

    private func knownBackupEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for rel in [
            "Library/Preferences/idevice_backups.json",
            "Library/Preferences/mobile_sync_backups.json",
            "Library/Application Support/MobileSync/backup_inventory.json",
            "Library/Logs/idevice_backups.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }
        return events
    }

    private func discoveredBackupEvents(_ root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for url in root.enumerate(matching: isBackupFile) where isBackupLocation(url) {
            if seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }
        return events
    }

    private func isBackupFile(_ url: URL) -> Bool {
        ["idevice_backups.json", "mobile_sync_backups.json", "backup_inventory.json", "idevice_backups.jsonl", "Info.plist.json"].contains(url.lastPathComponent)
    }

    private func isBackupLocation(_ url: URL) -> Bool {
        url.lastPathComponent != "Info.plist.json" || url.path.contains("MobileSync") || url.path.contains("Backup")
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["backups", "items", "devices"],
            identityKeys: ["device_name", "DeviceName", "encrypted", "IsEncrypted"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = backupDetails(item, sourceURL: sourceURL) else { return nil }
        let risks = backupRisks(item, details: details)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "backup.idevice",
                label: "IDEVICEBACKUP"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: details.eventTime,
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "idevice|\(details.deviceName.isEmpty ? details.udidMarker : details.deviceName)")],
                properties: backupFields(details, risks: risks),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func backupDetails(_ item: [String: Any], sourceURL: URL) -> BackupDetails? {
        let deviceName = firstString(item, keys: ["device_name", "DeviceName", "name"])
        let encrypted = firstBool(item, keys: ["encrypted", "IsEncrypted", "is_encrypted"])
        let lastBackup = firstString(item, keys: ["last_backup", "LastBackupDate", "timestamp"])
        guard !deviceName.isEmpty || encrypted != nil || !lastBackup.isEmpty else { return nil }
        return BackupDetails(
            deviceName: deviceName, encrypted: encrypted, lastBackup: lastBackup,
            product: firstString(item, keys: ["product_type", "ProductType", "product"]),
            iosVersion: firstString(item, keys: ["ios_version", "ProductVersion"]),
            udidMarker: marker(firstString(item, keys: ["udid_marker", "UniqueDeviceID", "udid"])),
            path: firstString(item, keys: ["backup_path", "path"]),
            user: stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? "",
            eventTime: parseDate(item["last_backup"] ?? item["LastBackupDate"] ?? item["timestamp"]) ?? Date(timeIntervalSince1970: 0)
        )
    }

    private func firstString(_ item: [String: Any], keys: [String]) -> String { keys.lazy.compactMap { stringish(item[$0]) }.first ?? "" }
    private func firstBool(_ item: [String: Any], keys: [String]) -> Bool? { keys.lazy.compactMap { boolish(item[$0]) }.first }
    private func marker(_ value: String) -> String { value.count > 12 ? String(value.prefix(8)) + "…" : value }

    private func backupRisks(_ item: [String: Any], details: BackupDetails) -> [String] {
        var risks = stringish(item["risk_tags"])?.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } ?? []
        if details.encrypted == false, !risks.contains("unencrypted_backup") { risks.append("unencrypted_backup") }
        if details.encrypted == true, !risks.contains("encrypted_backup") { risks.append("encrypted_backup") }
        if details.deviceName.lowercased().contains("evil"), !risks.contains("suspicious_device") { risks.append("suspicious_device") }
        return risks
    }

    private func backupFields(_ details: BackupDetails, risks: [String]) -> [String: String] {
        var fields: [String: String] = [
            "backup.device_name": details.deviceName, "backup.last_backup": details.lastBackup,
            "backup.product_type": details.product, "backup.ios_version": details.iosVersion,
            "backup.udid_marker": details.udidMarker, "backup.path": details.path,
            FieldTaxonomy.eventType: "backup.idevice",
            FieldTaxonomy.userName: details.user,
        ]
        if let enc = details.encrypted {
            fields["backup.encrypted"] = enc ? "true" : "false"
        }
        if !risks.isEmpty {
            fields["backup.risk_tags"] = risks.joined(separator: ",")
        }
        return fields
    }
}
