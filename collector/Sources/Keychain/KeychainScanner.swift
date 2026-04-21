import Foundation
import Security
import Models

/// Enumerates keychain items and extracts ACL metadata.
///
/// SECURITY: kSecReturnData is NEVER set to true. This scanner only reads
/// metadata (labels, services, access groups, trusted app lists).
/// No passwords, keys, or secret values are ever accessed.
struct KeychainScanner {

    func scan() -> (items: [KeychainItem], errors: [String]) {
        var items: [KeychainItem] = []
        var errors: [String] = []

        // Password classes: request item refs so we can extract ACL trusted apps
        for (secClass, kind) in [
            (kSecClassGenericPassword, KeychainItem.Kind.genericPassword),
            (kSecClassInternetPassword, KeychainItem.Kind.internetPassword),
        ] {
            let (i, e) = scanPasswordClass(secClass, kind: kind)
            items.append(contentsOf: i)
            errors.append(contentsOf: e)
        }

        // Cert/key classes: attributes only (different trust model; ACL via access group)
        for (secClass, kind) in [
            (kSecClassCertificate, KeychainItem.Kind.certificate),
            (kSecClassKey, KeychainItem.Kind.key),
        ] {
            let (i, e) = scanAttributesOnly(secClass, kind: kind)
            items.append(contentsOf: i)
            errors.append(contentsOf: e)
        }

        return (items, errors)
    }

    // MARK: - Password classes (generic + internet)

    private func scanPasswordClass(
        _ secClass: CFString,
        kind: KeychainItem.Kind
    ) -> ([KeychainItem], [String]) {
        // kSecReturnData is explicitly false — never read secret values
        let query: [CFString: Any] = [
            kSecClass: secClass,
            kSecReturnAttributes: kCFBooleanTrue!,
            kSecReturnRef: kCFBooleanTrue!,
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

        var items: [KeychainItem] = []
        var errors: [String] = []

        for attrs in records {
            let label       = resolveLabel(from: attrs)
            let service     = attrs[kSecAttrService as String] as? String
            let accessGroup = attrs[kSecAttrAccessGroup as String] as? String

            var trustedApps: [String] = []
            if let ref = attrs[kSecValueRef as String] {
                let (apps, err) = extractTrustedApps(from: ref)
                trustedApps = apps
                if let err { errors.append(err) }
            }

            items.append(KeychainItem(
                label: label, kind: kind,
                service: service, accessGroup: accessGroup,
                trustedApps: trustedApps
            ))
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

    // MARK: - ACL extraction

    /// Reads the trusted-application list from a file-based keychain item's ACL.
    /// Only reads metadata — no secret values are accessed.
    /// Falls back gracefully for Data Protection Keychain items and locked keychains.
    private func extractTrustedApps(from ref: Any) -> ([String], String?) {
        // CF types share the same opaque base type. The downcast from Any to
        // SecKeychainItem always succeeds at the type level; the real fallback
        // happens when the SecKeychainItemCopyAccess call below fails (e.g.,
        // Data Protection Keychain items on newer macOS versions).
        let keychainItem = ref as! SecKeychainItem  // swiftlint:disable:this force_cast

        var access: SecAccess?
        // Note: SecKeychainItemCopyAccess is deprecated in macOS 13 but still functional.
        // No modern replacement exists for reading ACL trusted-app metadata.
        let status = SecKeychainItemCopyAccess(keychainItem, &access)

        guard status == errSecSuccess, let access else {
            // These are expected non-error conditions:
            // errSecAuthFailed       — item owned by another process
            // errSecInteractionNotAllowed — keychain locked (e.g. screen locked)
            // errSecNoSuchAttr       — item has no legacy ACL (Data Protection Keychain)
            // errSecParam (-50)      — invalid item type for this API
            let silentErrors: [OSStatus] = [
                errSecAuthFailed,
                errSecInteractionNotAllowed,
                errSecNoSuchAttr,
                errSecParam,
                OSStatus(-2070),    // errSecInternalComponent
            ]
            if silentErrors.contains(status) { return ([], nil) }
            return ([], "SecKeychainItemCopyAccess: OSStatus \(status)")
        }

        var aclList: CFArray?
        SecAccessCopyACLList(access, &aclList)
        guard let acls = aclList as? [SecACL] else { return ([], nil) }

        var bundleIds: Set<String> = []

        for acl in acls {
            var appListRef: CFArray?
            var desc: CFString?
            var promptSelector = SecKeychainPromptSelector(rawValue: 0)
            SecACLCopyContents(acl, &appListRef, &desc, &promptSelector)
            guard let apps = appListRef as? [SecTrustedApplication] else { continue }

            for app in apps {
                var dataRef: CFData?
                guard SecTrustedApplicationCopyData(app, &dataRef) == errSecSuccess,
                      let cfData = dataRef else { continue }

                let raw = cfData as Data
                // Data is a null-terminated UTF-8 path
                let pathData: Data
                if let nullIdx = raw.firstIndex(of: 0) {
                    pathData = raw[..<nullIdx]
                } else {
                    pathData = raw
                }
                guard let path = String(data: pathData, encoding: .utf8),
                      !path.isEmpty else { continue }

                bundleIds.insert(bundleIdForPath(path) ?? path)
            }
        }

        return (Array(bundleIds), nil)
    }

    // MARK: - Helpers

    private func resolveLabel(from attrs: [String: Any]) -> String {
        let candidateKeys = [kSecAttrLabel as String, kSecAttrService as String, kSecAttrAccount as String]
        for key in candidateKeys {
            if let value = attrs[key] as? String, !value.isEmpty { return value }
        }
        return "Unlabeled"
    }

    /// Map an executable path or app bundle path to a bundle identifier.
    private func bundleIdForPath(_ path: String) -> String? {
        // Direct .app bundle
        if path.hasSuffix(".app") {
            return Bundle(path: path)?.bundleIdentifier
        }
        // Executable inside a .app bundle — walk up directory tree
        var url = URL(fileURLWithPath: path)
        while url.pathComponents.count > 2 {
            url = url.deletingLastPathComponent()
            if url.pathExtension == "app" {
                return Bundle(url: url)?.bundleIdentifier
            }
        }
        return nil
    }

    private func describeError(kind: KeychainItem.Kind, status: OSStatus) -> String {
        if status == errSecInteractionNotAllowed {
            return "Keychain locked — \(kind.rawValue) items skipped (unlock screen and retry)"
        }
        return "SecItemCopyMatching(\(kind.rawValue)): OSStatus \(status)"
    }
}
