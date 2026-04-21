import Foundation

/// A discovered macOS .app bundle with entitlement and code signing metadata.
public struct Application: Codable, Sendable, GraphNode {
    public let name: String
    public let bundleId: String
    public let path: String
    public let version: String?
    public let teamId: String?
    public let hardenedRuntime: Bool
    public let libraryValidation: Bool
    public let isElectron: Bool
    public let isSystem: Bool
    public let signed: Bool
    public let isSipProtected: Bool
    public let isSandboxed: Bool
    public let sandboxExceptions: [String]
    public let isNotarized: Bool?
    public let isAdhocSigned: Bool
    public let signingCertificateCN: String?
    public let signingCertificateSHA256: String?
    public let certificateExpires: String?
    public let isCertificateExpired: Bool
    public let certificateChainLength: Int?
    public let certificateTrustValid: Bool?
    public let certificateChain: [CertificateDetail]
    public let entitlements: [EntitlementInfo]
    public let injectionMethods: [InjectionMethod]
    public let launchConstraintCategory: String?
    public let sandboxProfile: SandboxProfile?
    public let quarantineInfo: QuarantineInfo?

    public var nodeType: String { "Application" }

    public init(
        name: String,
        bundleId: String,
        path: String,
        version: String?,
        teamId: String?,
        hardenedRuntime: Bool,
        libraryValidation: Bool,
        isElectron: Bool,
        isSystem: Bool,
        signed: Bool,
        isSipProtected: Bool = false,
        isSandboxed: Bool = false,
        sandboxExceptions: [String] = [],
        isNotarized: Bool? = nil,
        isAdhocSigned: Bool = false,
        signingCertificateCN: String? = nil,
        signingCertificateSHA256: String? = nil,
        certificateExpires: String? = nil,
        isCertificateExpired: Bool = false,
        certificateChainLength: Int? = nil,
        certificateTrustValid: Bool? = nil,
        certificateChain: [CertificateDetail] = [],
        entitlements: [EntitlementInfo] = [],
        injectionMethods: [InjectionMethod] = [],
        launchConstraintCategory: String? = nil,
        sandboxProfile: SandboxProfile? = nil,
        quarantineInfo: QuarantineInfo? = nil
    ) {
        self.name = name
        self.bundleId = bundleId
        self.path = path
        self.version = version
        self.teamId = teamId
        self.hardenedRuntime = hardenedRuntime
        self.libraryValidation = libraryValidation
        self.isElectron = isElectron
        self.isSystem = isSystem
        self.signed = signed
        self.isSipProtected = isSipProtected
        self.isSandboxed = isSandboxed
        self.sandboxExceptions = sandboxExceptions
        self.isNotarized = isNotarized
        self.isAdhocSigned = isAdhocSigned
        self.signingCertificateCN = signingCertificateCN
        self.signingCertificateSHA256 = signingCertificateSHA256
        self.certificateExpires = certificateExpires
        self.isCertificateExpired = isCertificateExpired
        self.certificateChainLength = certificateChainLength
        self.certificateTrustValid = certificateTrustValid
        self.certificateChain = certificateChain
        self.entitlements = entitlements
        self.injectionMethods = injectionMethods
        self.launchConstraintCategory = launchConstraintCategory
        self.sandboxProfile = sandboxProfile
        self.quarantineInfo = quarantineInfo
    }

    enum CodingKeys: String, CodingKey {
        case name
        case bundleId = "bundle_id"
        case path
        case version
        case teamId = "team_id"
        case hardenedRuntime = "hardened_runtime"
        case libraryValidation = "library_validation"
        case isElectron = "is_electron"
        case isSystem = "is_system"
        case signed
        case isSipProtected = "is_sip_protected"
        case isSandboxed = "is_sandboxed"
        case sandboxExceptions = "sandbox_exceptions"
        case isNotarized = "is_notarized"
        case isAdhocSigned = "is_adhoc_signed"
        case signingCertificateCN = "signing_certificate_cn"
        case signingCertificateSHA256 = "signing_certificate_sha256"
        case certificateExpires = "certificate_expires"
        case isCertificateExpired = "is_certificate_expired"
        case certificateChainLength = "certificate_chain_length"
        case certificateTrustValid = "certificate_trust_valid"
        case certificateChain = "certificate_chain"
        case entitlements
        case injectionMethods = "injection_methods"
        case launchConstraintCategory = "launch_constraint_category"
        case sandboxProfile = "sandbox_profile"
        case quarantineInfo = "quarantine_info"
    }
}

// MARK: - Builder methods for single-field enrichment

extension Application {
    /// Returns a copy with a different sandboxProfile, preserving all other fields.
    public func with(sandboxProfile newProfile: SandboxProfile?) -> Application {
        Application(
            name: name, bundleId: bundleId, path: path, version: version,
            teamId: teamId, hardenedRuntime: hardenedRuntime,
            libraryValidation: libraryValidation, isElectron: isElectron,
            isSystem: isSystem, signed: signed, isSipProtected: isSipProtected,
            isSandboxed: isSandboxed, sandboxExceptions: sandboxExceptions,
            isNotarized: isNotarized, isAdhocSigned: isAdhocSigned,
            signingCertificateCN: signingCertificateCN,
            signingCertificateSHA256: signingCertificateSHA256,
            certificateExpires: certificateExpires,
            isCertificateExpired: isCertificateExpired,
            certificateChainLength: certificateChainLength,
            certificateTrustValid: certificateTrustValid,
            certificateChain: certificateChain, entitlements: entitlements,
            injectionMethods: injectionMethods,
            launchConstraintCategory: launchConstraintCategory,
            sandboxProfile: newProfile,
            quarantineInfo: quarantineInfo
        )
    }

    /// Returns a copy with different quarantineInfo, preserving all other fields.
    public func with(quarantineInfo newInfo: QuarantineInfo?) -> Application {
        Application(
            name: name, bundleId: bundleId, path: path, version: version,
            teamId: teamId, hardenedRuntime: hardenedRuntime,
            libraryValidation: libraryValidation, isElectron: isElectron,
            isSystem: isSystem, signed: signed, isSipProtected: isSipProtected,
            isSandboxed: isSandboxed, sandboxExceptions: sandboxExceptions,
            isNotarized: isNotarized, isAdhocSigned: isAdhocSigned,
            signingCertificateCN: signingCertificateCN,
            signingCertificateSHA256: signingCertificateSHA256,
            certificateExpires: certificateExpires,
            isCertificateExpired: isCertificateExpired,
            certificateChainLength: certificateChainLength,
            certificateTrustValid: certificateTrustValid,
            certificateChain: certificateChain, entitlements: entitlements,
            injectionMethods: injectionMethods,
            launchConstraintCategory: launchConstraintCategory,
            sandboxProfile: sandboxProfile,
            quarantineInfo: newInfo
        )
    }
}
