import Foundation
import Models

/// Classifies raw entitlement keys into `EntitlementInfo` values.
struct EntitlementClassifier {

    private enum Category: String {
        case tcc
        case injection
        case privilege
        case sandbox
        case keychain
        case network
        case icloud
        case other

        var isSecurityCritical: Bool {
            switch self {
            case .tcc, .injection, .privilege: return true
            default: return false
            }
        }
    }

    /// Convert a raw entitlements dictionary into classified `EntitlementInfo` values.
    func classify(_ entitlements: [String: Any]) -> [EntitlementInfo] {
        return entitlements.keys.map { key in
            let category = categorize(key)
            let isPrivate = key.contains("com.apple.private.")
            return EntitlementInfo(
                name: key,
                isPrivate: isPrivate,
                category: category.rawValue,
                isSecurityCritical: category.isSecurityCritical
            )
        }.sorted { $0.name < $1.name }
    }

    /// Result of sandbox analysis from entitlements.
    struct SandboxInfo {
        let isSandboxed: Bool
        let exceptions: [String]
    }

    private static let sandboxEntitlement = "com.apple.security.app-sandbox"
    private static let sandboxExceptionPrefix = "com.apple.security.temporary-exception."

    /// Determine sandbox status and exception keys from raw entitlements.
    func analyzeSandbox(_ entitlements: [String: Any]) -> SandboxInfo {
        let isSandboxed = entitlements[Self.sandboxEntitlement] as? Bool ?? false
        let exceptions = entitlements.keys.filter { $0.hasPrefix(Self.sandboxExceptionPrefix) }.sorted()
        return SandboxInfo(isSandboxed: isSandboxed, exceptions: exceptions)
    }

    // MARK: - Private

    private func categorize(_ name: String) -> Category {
        // TCC-related private entitlements
        if name.hasPrefix("com.apple.private.tcc.") { return .tcc }

        // Injection-enabling entitlements
        if name == "com.apple.security.cs.allow-dyld-environment-variables" { return .injection }
        if name == "com.apple.security.cs.disable-library-validation" { return .injection }
        if name == "com.apple.security.cs.allow-unsigned-executable-memory" { return .injection }
        if name == "com.apple.security.cs.disable-executable-page-protection" { return .injection }

        // Privilege-granting entitlements
        if name == "com.apple.security.get-task-allow" { return .privilege }
        if name == "com.apple.security.cs.debugger" { return .privilege }
        if name.hasPrefix("com.apple.rootless.") { return .privilege }
        // Endpoint Security Framework — injectable ESF client can blind monitoring
        if name == "com.apple.developer.endpoint-security.client" { return .privilege }
        // Network extensions — injectable VPN/content-filter can intercept all traffic
        if name == "com.apple.developer.networking.vpn.api" { return .privilege }
        if name == "com.apple.developer.networking.networkextension" { return .privilege }

        // Sandbox-related
        if name == "com.apple.security.app-sandbox" { return .sandbox }
        if name.hasPrefix("com.apple.security.temporary-exception.") { return .sandbox }

        // Network
        if name.hasPrefix("com.apple.security.network.") { return .network }

        // Keychain
        if name == "keychain-access-groups" { return .keychain }
        if name == "com.apple.security.smartcard" { return .keychain }

        // iCloud / CloudKit / Ubiquity
        if name.hasPrefix("com.apple.developer.icloud-") { return .icloud }
        if name.hasPrefix("com.apple.developer.ubiquity-") { return .icloud }
        if name.hasPrefix("com.apple.developer.cloudkit") { return .icloud }

        return .other
    }
}
