import Foundation
import RootstockBlueCore

/// Multi-provider cloud-sync **posture markers** beyond iCloud.
///
/// Covers Dropbox, OneDrive, Google Drive, Box, and similar clients,
/// account markers, sync enablement, and folder paths for exfil IR.
/// Does not dump full cloud file listings or account secrets.
public struct CloudSyncParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CLOUDSYNC",
        tier: .tier2,
        description: "Multi-provider cloud sync markers (Dropbox/OneDrive/GDrive/Box)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        let configured = Self.configuredPaths.compactMap { root.firstExisting([$0]) }
        let discovered = root.enumerate(matching: { Self.artifactNames.contains($0.lastPathComponent) })
        for url in configured + discovered where seen.insert(url) {
            events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["providers", "items", "accounts"],
            identityKeys: ["provider", "sync_enabled"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let record = CloudSyncRecord(item: item, sourceURL: sourceURL, inferredProvider: inferredProvider)
        guard record.isMeaningful else { return nil }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "cloud.provider_sync",
                label: "CLOUDSYNC"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["last_sync"] ?? item["timestamp"]) ?? Date(),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: record.entities,
                properties: record.fields,
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private static let configuredPaths = [
        "Library/Preferences/cloud_sync.json", "Library/Preferences/cloud_providers.json",
        "Library/Preferences/dropbox_sync.json", "Library/Preferences/onedrive_sync.json", "Library/Logs/cloud_sync.jsonl",
    ]

    private static let artifactNames: Set<String> = [
        "cloud_sync.json", "cloud_providers.json", "dropbox_sync.json", "onedrive_sync.json",
        "gdrive_sync.json", "box_sync.json", "cloud_sync.jsonl",
    ]

    private struct CloudSyncRecord {
        let provider: String
        let accountMarker: String
        let syncEnabled: Bool
        let folderPath: String
        let selectiveSync: Bool
        let user: String
        let riskTags: [String]

        init(item: [String: Any], sourceURL: URL, inferredProvider: (String) -> String) {
            let suppliedProvider = Self.firstString(in: item, keys: ["provider", "name", "service"])
            provider = suppliedProvider.isEmpty ? inferredProvider(sourceURL.path) : suppliedProvider
            syncEnabled = Self.firstBool(in: item, keys: ["sync_enabled", "enabled"]) ?? true
            folderPath = Self.firstString(in: item, keys: ["folder_path", "path", "sync_folder"])
            accountMarker = Self.maskedAccountMarker(Self.firstString(in: item, keys: ["account_marker", "account", "email"]))
            selectiveSync = boolish(item["selective_sync"]) ?? false
            user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""
            riskTags = Self.riskTags(item: item, provider: provider, folderPath: folderPath, syncEnabled: syncEnabled)
        }

        var isMeaningful: Bool { !provider.isEmpty || !folderPath.isEmpty || syncEnabled }
        var entities: [EntityID] { [EntityID(kind: .host, value: "cloud|\(normalizedProvider)|\(accountMarker)")] }

        var fields: [String: String] {
            var values: [String: String] = ["cloud.provider": normalizedProvider, "cloud.account_marker": accountMarker, "cloud.sync_enabled": syncEnabled ? "true" : "false", "cloud.folder_path": folderPath, "cloud.selective_sync": selectiveSync ? "true" : "false", FieldTaxonomy.eventType: "cloud.provider_sync", FieldTaxonomy.userName: user]
            if !riskTags.isEmpty { values["cloud.risk_tags"] = riskTags.joined(separator: ",") }
            return values
        }

        private var normalizedProvider: String { provider.isEmpty ? "unknown" : provider.lowercased() }
        private static func firstString(in item: [String: Any], keys: [String]) -> String { keys.lazy.compactMap { stringish(item[$0]) }.first ?? "" }
        private static func firstBool(in item: [String: Any], keys: [String]) -> Bool? { keys.lazy.compactMap { boolish(item[$0]) }.first }
        private static func maskedAccountMarker(_ value: String) -> String {
            let parts = value.split(separator: "@")
            return parts.count == 2 ? "***@" + String(parts[1]) : value
        }
        private static func riskTags(item: [String: Any], provider: String, folderPath: String, syncEnabled: Bool) -> [String] {
            var tags = stringish(item["risk_tags"])? .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } ?? []
            let additions = [
                syncEnabled ? "sync_enabled" : nil,
                syncEnabled && isExfilCapableProvider(provider) ? "exfil_capable_provider" : nil,
                hasSensitiveFolderScope(folderPath) ? "desktop_documents_scope" : nil,
                isSuspiciousProvider(provider, folderPath: folderPath) ? "suspicious_provider" : nil,
            ].compactMap { $0 }
            for tag in additions where !tags.contains(tag) { tags.append(tag) }
            return tags
        }

        private static func isExfilCapableProvider(_ provider: String) -> Bool {
            ["dropbox", "onedrive", "google_drive", "gdrive", "box", "mega", "pcloud"].contains(provider.lowercased())
        }

        private static func hasSensitiveFolderScope(_ folderPath: String) -> Bool {
            ["desktop", "documents"].contains(where: folderPath.lowercased().contains)
        }

        private static func isSuspiciousProvider(_ provider: String, folderPath: String) -> Bool {
            provider.lowercased().contains("evil") || folderPath.lowercased().contains("evil")
        }
    }

    private func inferredProvider(from path: String) -> String {
        let markers = [("dropbox", "dropbox"), ("onedrive", "onedrive"), ("gdrive", "google_drive"), ("google", "google_drive"), ("box", "box")]
        return markers.first { path.lowercased().contains($0.0) }?.1 ?? ""
    }

    private func cloudRiskTags(provider: String, folderPath: String, syncEnabled: Bool) -> [String] {
        let providerName = provider.lowercased()
        let folder = folderPath.lowercased()
        let knownExfil = ["dropbox", "onedrive", "google_drive", "gdrive", "box", "mega", "pcloud"]
        return [
            syncEnabled ? "sync_enabled" : nil,
            syncEnabled && knownExfil.contains(providerName) ? "exfil_capable_provider" : nil,
            ["desktop", "documents"].contains(where: folder.contains) ? "desktop_documents_scope" : nil,
            folder.contains("evil") || providerName.contains("evil") ? "suspicious_provider" : nil,
        ].compactMap { $0 }
    }

    private func appendRiskTags(_ additions: [String], to tags: inout [String]) {
        for tag in additions where !tags.contains(tag) { tags.append(tag) }
    }
}
