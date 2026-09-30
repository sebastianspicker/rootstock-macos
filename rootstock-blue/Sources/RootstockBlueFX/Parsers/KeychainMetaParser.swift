import Foundation
import RootstockBlueCore

/// Keychain metadata inventory from collector/fixture JSON exports.
///
/// Emits item class, label, access group, account (username-like), and mtime only.
///
/// Non-goal: Never emit password, secret, key material, private keys, tokens,
/// or any `kSecValueData`-equivalent fields. Metadata hunting only (labels,
/// access groups, generic-password presence in system keychains).
public struct KeychainMetaParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "KEYCHAINMETA",
        tier: .tier2,
        description: "Keychain item metadata only (no secrets/passwords/keys)"
    )

    /// Field names that must never be copied into envelopes (defense in depth).
    private static let forbiddenKeys: Set<String> = [
        "password", "secret", "key", "private_key", "privatekey", "token",
        "ksecvaluedata", "data", "value_data", "credential", "passwd",
        "passphrase", "api_key", "apikey", "auth_token", "refresh_token",
        "session_key", "symmetric_key", "key_data", "secret_data",
    ]

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/keychain_metadata.json",
            "Library/Preferences/keychain_meta.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url), defaultUser: nil))
            }
        }

        // Users/*/Library/Preferences/keychain_metadata.json
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "keychain_metadata.json" || name == "keychain_meta.json"
        }) {
            guard seen.insert(url) else { continue }
            let key = ArtifactRoot.pathKey(url)
            if let json = ArtifactIO.jsonObject(contentsOf: url) {
                events.append(contentsOf: parseJSONInventory(
                    json,
                    rawRef: key,
                    defaultUser: inferUser(from: key)
                ))
            }
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String, defaultUser: String?) -> [EventEnvelope] {
        let items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["items", "entries", "keychain", "metadata"],
            identityKeys: ["label", "item_class", "access_group"]
        )
        return items.compactMap { makeEvent(from: $0, rawRef: rawRef, defaultUser: defaultUser) }
    }

    private func makeEvent(from item: [String: Any], rawRef: String, defaultUser: String?) -> EventEnvelope? {
        let record = KeychainMetadataRecord(item: item, rawRef: rawRef, defaultUser: defaultUser)
        guard record.isMeaningful else { return nil }
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "keychain.metadata",
                label: "KEYCHAINMETA"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(record.timestamp) ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: record.entities,
                properties: record.fields,
                provenance: rawRef,
                confidence: 0.91
            )
        )
    }

    private struct KeychainMetadataRecord {
        let itemClass: String
        let label: String
        let accessGroup: String
        let account: String
        let mtime: String
        let timestamp: Any?
        let user: String?
        let rawRef: String
        let riskTags: [String]

        init(item: [String: Any], rawRef: String, defaultUser: String?) {
            let sanitized = item.filter { key, _ in !KeychainMetaParser.forbiddenKeys.contains(key.lowercased().replacingOccurrences(of: "-", with: "_")) }
            itemClass = Self.firstString(in: sanitized, keys: ["item_class", "class", "kSecClass"])
            label = Self.firstString(in: sanitized, keys: ["label", "labl", "service"])
            accessGroup = Self.firstString(in: sanitized, keys: ["access_group", "agrp", "accessGroup"])
            account = Self.firstString(in: sanitized, keys: ["account", "acct", "username", "user"])
            mtime = Self.firstString(in: sanitized, keys: ["mtime", "modification_date", "modified", "cdat"])
            timestamp = sanitized["mtime"] ?? sanitized["modification_date"] ?? sanitized["timestamp"]
            user = defaultUser ?? inferUser(from: rawRef)
            self.rawRef = rawRef
            riskTags = Self.riskTags(item: sanitized, itemClass: itemClass, label: label, accessGroup: accessGroup, rawRef: rawRef)
        }

        var isMeaningful: Bool { !itemClass.isEmpty || !label.isEmpty || !accessGroup.isEmpty || !account.isEmpty }
        var fields: [String: String] {
            var values: [String: String] = ["keychain.item_class": itemClass, "keychain.label": label, "keychain.access_group": accessGroup, "keychain.account": account, "keychain.mtime": mtime, FieldTaxonomy.eventType: "keychain.metadata"]
            if !riskTags.isEmpty { values["keychain.risk_tags"] = riskTags.joined(separator: ",") }
            if let user { values[FieldTaxonomy.userName] = user }
            return values
        }
        var entities: [EntityID] {
            var values: [EntityID] = [EntityID(kind: .auth, value: "keychain|\(itemClass)|\(label)|\(account)"), .file(path: rawRef)]
            if let user { values.append(.user(name: user)) }
            return values
        }
        private static func firstString(in item: [String: Any], keys: [String]) -> String { keys.lazy.compactMap { stringish(item[$0]) }.first ?? "" }
        private static func riskTags(item: [String: Any], itemClass: String, label: String, accessGroup: String, rawRef: String) -> [String] {
            var tags = stringish(item["risk_tags"])? .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) } ?? []
            append("suspicious_label", when: isSuspiciousLabel(label), to: &tags)
            append("unexpected_access_group", when: isUnexpectedAccessGroup(accessGroup, item: item), to: &tags)
            append("generic_password_in_system", when: isSystemGenericPassword(itemClass, rawRef: rawRef, item: item), to: &tags)
            return tags
        }
        private static func isSuspiciousLabel(_ label: String) -> Bool { ["evil", "implant", "backdoor"].contains(where: label.lowercased().contains) }
        private static func isUnexpectedAccessGroup(_ accessGroup: String, item: [String: Any]) -> Bool {
            let group = accessGroup.lowercased()
            let nonAppleGroup = !accessGroup.isEmpty && !group.hasPrefix("apple") && !group.hasPrefix("com.apple")
            return nonAppleGroup && (group.contains("evil") || group.contains("unknown") || boolish(item["unexpected_access_group"]) == true)
        }
        private static func isSystemGenericPassword(_ itemClass: String, rawRef: String, item: [String: Any]) -> Bool {
            let itemType = itemClass.lowercased()
            let genericPassword = itemType.contains("generic") || itemType == "genp" || itemType.contains("internet")
            let systemScope = rawRef.contains("/Library/Preferences/keychain") && !rawRef.contains("/Users/")
            return genericPassword && (systemScope || boolish(item["system_keychain"]) == true)
        }
        private static func append(_ tag: String, when condition: Bool, to tags: inout [String]) { if condition && !tags.contains(tag) { tags.append(tag) } }
    }
}
