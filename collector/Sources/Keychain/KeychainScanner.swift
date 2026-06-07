import Foundation
import Security
import Models

/// Enumerates non-secret keychain item metadata.
///
/// SECURITY: kSecReturnData is NEVER set to true. This scanner only reads
/// metadata (labels, services, access groups, trusted app lists).
/// Password item classes are intentionally not queried so password-bearing
/// items cannot transit collector memory.
struct KeychainScanner {
    static let scannedItemClasses: [(secClass: CFString, kind: KeychainItem.Kind)] = [
        (kSecClassCertificate, .certificate),
        (kSecClassKey, .key),
    ]

    func scan() -> (items: [KeychainItem], errors: [String]) {
        var items: [KeychainItem] = []
        var errors: [String] = []

        for (secClass, kind) in Self.scannedItemClasses {
            let (i, e) = scanAttributesOnly(secClass, kind: kind)
            items.append(contentsOf: i)
            errors.append(contentsOf: e)
        }

        return (items, errors)
    }

    // MARK: - Certificate / Key classes (attributes only)

    private func scanAttributesOnly(
        _ secClass: CFString,
        kind: KeychainItem.Kind
    ) -> ([KeychainItem], [String]) {
        let query: [CFString: Any] = [
            kSecClass: secClass,
            kSecReturnAttributes: kCFBooleanTrue!,
            kSecReturnData: kCFBooleanFalse!,
            kSecMatchLimit: kSecMatchLimitAll,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound { return ([], []) }
            return ([], [describeError(kind: kind, status: status)])
        }
        guard let records = result as? [[String: Any]] else { return ([], []) }

        return (records.map { attrs in
            KeychainItem(
                label: resolveLabel(from: attrs),
                kind: kind,
                service: attrs[kSecAttrService as String] as? String,
                accessGroup: attrs[kSecAttrAccessGroup as String] as? String,
                trustedApps: []
            )
        }, [])
    }

    // MARK: - Helpers

    private func resolveLabel(from attrs: [String: Any]) -> String {
        let candidateKeys = [kSecAttrLabel as String, kSecAttrService as String, kSecAttrAccount as String]
        for key in candidateKeys {
            if let value = attrs[key] as? String, !value.isEmpty { return value }
        }
        return "Unlabeled"
    }

    private func describeError(kind: KeychainItem.Kind, status: OSStatus) -> String {
        if status == errSecInteractionNotAllowed {
            return "Keychain locked — \(kind.rawValue) items skipped (unlock screen and retry)"
        }
        return "SecItemCopyMatching(\(kind.rawValue)): OSStatus \(status)"
    }
}
