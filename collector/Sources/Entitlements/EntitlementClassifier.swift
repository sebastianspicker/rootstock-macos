import Foundation
import Models

/// Classifies raw entitlement keys into `EntitlementInfo` values.
struct EntitlementClassifier: Sendable {

    private enum Category: String, Sendable {
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

    private struct CategoryRule: Sendable {
        let category: Category
        let exactMatches: Set<String>
        let prefixes: [String]

        func matches(_ name: String) -> Bool {
            exactMatches.contains(name) || prefixes.contains { name.hasPrefix($0) }
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
    struct SandboxInfo: Sendable {
        let isSandboxed: Bool
        let exceptions: [String]
    }

    private static let sandboxEntitlement = "com.apple.security.app-sandbox"
    private static let sandboxExceptionPrefix = "com.apple.security.temporary-exception."
    private static let categoryRules: [CategoryRule] = [
        CategoryRule(
            category: .tcc,
            exactMatches: [],
            prefixes: ["com.apple.private.tcc."]
        ),
        CategoryRule(
            category: .injection,
            exactMatches: [
                "com.apple.security.cs.allow-dyld-environment-variables",
                "com.apple.security.cs.disable-library-validation",
                "com.apple.security.cs.allow-unsigned-executable-memory",
                "com.apple.security.cs.disable-executable-page-protection",
            ],
            prefixes: []
        ),
        CategoryRule(
            category: .privilege,
            exactMatches: [
                "com.apple.security.get-task-allow",
                "com.apple.security.cs.debugger",
                "com.apple.developer.endpoint-security.client",
                "com.apple.developer.networking.vpn.api",
                "com.apple.developer.networking.networkextension",
            ],
            prefixes: ["com.apple.rootless."]
        ),
        CategoryRule(
            category: .sandbox,
            exactMatches: [sandboxEntitlement],
            prefixes: [sandboxExceptionPrefix]
        ),
        CategoryRule(
            category: .network,
            exactMatches: [],
            prefixes: ["com.apple.security.network."]
        ),
        CategoryRule(
            category: .keychain,
            exactMatches: [
                "keychain-access-groups",
                "com.apple.security.smartcard",
            ],
            prefixes: []
        ),
        CategoryRule(
            category: .icloud,
            exactMatches: [],
            prefixes: [
                "com.apple.developer.icloud-",
                "com.apple.developer.ubiquity-",
                "com.apple.developer.cloudkit",
            ]
        ),
    ]

    /// Determine sandbox status and exception keys from raw entitlements.
    func analyzeSandbox(_ entitlements: [String: Any]) -> SandboxInfo {
        let isSandboxed = entitlements[Self.sandboxEntitlement] as? Bool ?? false
        let exceptions = entitlements.keys.filter { $0.hasPrefix(Self.sandboxExceptionPrefix) }.sorted()
        return SandboxInfo(isSandboxed: isSandboxed, exceptions: exceptions)
    }

    // MARK: - Private

    private func categorize(_ name: String) -> Category {
        Self.categoryRules.first { $0.matches(name) }?.category ?? .other
    }
}
