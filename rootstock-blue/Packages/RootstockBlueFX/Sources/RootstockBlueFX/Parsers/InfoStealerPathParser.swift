import Foundation
import RootstockBlueCore

/// Info-stealer multi-app **path plane** markers (Wave-8 residual red↔blue pair).
///
/// Inventories browser / messaging / vault / wallet / sync path families for IR.
/// **NEVER exports secrets** - no password, cookie, keychain, or wallet material.
public struct InfoStealerPathParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "INFOSTEALERPATH",
        tier: .tier2,
        description: "Info-stealer multi-app collection path plane (no secrets)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/stealer_path_plane.json",
            "Library/Logs/stealer_path_plane.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "stealer_path_plane.json" || name == "stealer_path_plane.jsonl"
        }) where seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return ArtifactIO.jsonlDictionaries(contentsOf: url)
                .compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["paths", "items", "entries", "targets"],
            identityKeys: ["path_family", "path", "stealer_path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = stealerDetails(from: item, sourceURL: sourceURL) else { return nil }
        let fields = stealerFields(details: details)
        return stealerEnvelope(item: item, sourceURL: sourceURL, details: details, fields: fields)
    }

    private struct StealerDetails {
        let family: String
        let path: String
        let fdaAdjacent: Bool
        let user: String
        let risk: [String]
    }

    private func stealerDetails(from item: [String: Any], sourceURL: URL) -> StealerDetails? {
        discardSecretMarkers(in: item)
        let path = stringish(item["path"]) ?? stringish(item["stealer_path"]) ?? stringish(item["target_path"]) ?? ""
        guard !path.isEmpty else { return nil }
        let family = normalizedFamily(item: item, path: path)
        let fdaAdjacent = boolish(item["fda_adjacent"]) ?? boolish(item["requires_fda"]) ?? pathLooksFDAAdjacent(path)
        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        return StealerDetails(family: family, path: path, fdaAdjacent: fdaAdjacent, user: user, risk: stealerRisk(item: item, fdaAdjacent: fdaAdjacent))
    }

    private func discardSecretMarkers(in item: [String: Any]) {
        for key in ["password", "cookie", "cookie_value", "secret", "token", "keychain_data", "wallet_seed", "mnemonic", "private_key"] where item[key] != nil { _ = key }
    }

    private func normalizedFamily(item: [String: Any], path: String) -> String {
        let allowed = ["browser", "messaging", "vault", "wallet", "sync"]
        let supplied = (stringish(item["path_family"]) ?? stringish(item["family"]) ?? stringish(item["category"]) ?? "").lowercased()
        let inferred = supplied.isEmpty ? inferFamily(from: path) : supplied
        return allowed.contains(inferred) ? inferred : (allowed.contains(inferFamily(from: path)) ? inferFamily(from: path) : "browser")
    }

    private func stealerRisk(item: [String: Any], fdaAdjacent: Bool) -> [String] {
        var risk = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { tag in
            let lower = tag.lowercased()
            return !lower.contains("password_dump") && !lower.contains("cookie_value")
        }
        if fdaAdjacent, !risk.contains("fda_adjacent") { risk.append("fda_adjacent") }
        return risk
    }

    private func stealerFields(details: StealerDetails) -> [String: String] {
        var fields = ["stealer.path_family": details.family, "stealer.path": details.path, "stealer.fda_adjacent": details.fdaAdjacent ? "true" : "false", FieldTaxonomy.eventType: "stealer.path", FieldTaxonomy.userName: details.user]
        if !details.risk.isEmpty { fields["stealer.risk_tags"] = details.risk.joined(separator: ",") }
        fields["stealer.secrets_exported"] = "false"
        return fields
    }

    private func stealerEnvelope(item: [String: Any], sourceURL: URL, details: StealerDetails, fields: [String: String]) -> EventEnvelope {
        EventEnvelope(identity: EventEnvelope.Identity(kind: "stealer.path", label: "INFOSTEALERPATH"), capture: EventEnvelope.Capture(source: .parser, eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(), collectedAt: Date()), payload: EventEnvelope.Payload(entityRefs: [EntityID(kind: .host, value: "stealer|\(details.family)|\(details.path.hashValue)")], properties: fields, provenance: ArtifactRoot.pathKey(sourceURL), confidence: 0.88))
    }

    private static let familyMarkers: [(family: String, markers: [String])] = [
        ("browser", ["chrome", "firefox", "safari", "edge", "brave", "cookies"]),
        ("messaging", ["slack", "telegram", "discord", "messages", "mail"]),
        ("vault", ["1password", "bitwarden", "keepass", "keychain", "notes"]),
        ("wallet", ["exodus", "electrum", "coinomi", "ledger", "wallet"]),
        ("sync", ["dropbox", "cloudstorage", "mobile documents", "desktop", "documents", "downloads"]),
    ]

    private func inferFamily(from path: String) -> String {
        let normalizedPath = path.lowercased()
        return Self.familyMarkers.first {
            $0.markers.contains(where: normalizedPath.contains)
        }?.family ?? "browser"
    }

    private func pathLooksFDAAdjacent(_ path: String) -> Bool {
        let p = path.lowercased()
        return p.contains("tcc")
            || p.contains("full disk")
            || p.contains("/library/application support/com.apple.tcc")
            || p.contains("keychains")
            || p.contains("messages")
            || p.contains("mail")
            || p.contains("safari")
    }
}
