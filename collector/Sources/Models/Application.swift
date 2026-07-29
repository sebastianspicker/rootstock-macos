import Foundation

/// A discovered macOS .app bundle with entitlement and code signing metadata.
public struct Application: Codable, Sendable, GraphNode {
    public let name: String
    public let bundleId: String
    public let path: String
    public let version: String?
    public let teamId: String?
    public let hardenedRuntime: Bool?
    public let libraryValidation: Bool?
    public let isElectron: Bool
    public let isSystem: Bool
    public let signed: Bool?
    public let codeSigningAnalysisError: Bool
    public let isSipProtected: Bool
    public let isSandboxed: Bool
    public let sandboxExceptions: [String]
    public let entitlementsAvailable: Bool
    public let entitlementExtractionError: String?
    public let signingCertificateCN: String?
    public let signingCertificateSHA256: String?
    public let certificateExpires: String?
    public let isCertificateExpired: Bool
    public let certificateChainLength: Int?
    public let certificateTrustValid: Bool?
    public let certificateChain: [CertificateDetail]
    public let isNotarized: Bool?
    public let isAdhocSigned: Bool
    public let entitlements: [EntitlementInfo]
    public let injectionMethods: [InjectionMethod]
    public let launchConstraintCategory: String?
    public let sandboxProfile: SandboxProfile?
    public let quarantineInfo: QuarantineInfo?

    public var nodeType: String { "Application" }

    public struct Identity: Codable, Sendable {
        public let name: String
        public let bundleId: String
        public let path: String
        public let version: String?

        public init(name: String, bundleId: String, path: String, version: String?) {
            self.name = name
            self.bundleId = bundleId
            self.path = path
            self.version = version
        }
    }

    public struct Flags: Codable, Sendable {
        public let isElectron: Bool
        public let isSystem: Bool

        public init(isElectron: Bool, isSystem: Bool) {
            self.isElectron = isElectron
            self.isSystem = isSystem
        }
    }

    public struct Signing: Codable, Sendable {
        public let teamId: String?
        public let hardenedRuntime: Bool?
        public let libraryValidation: Bool?
        public let signed: Bool?
        public let codeSigningAnalysisError: Bool
        public let isNotarized: Bool?
        public let isAdhocSigned: Bool
        public let signingCertificateCN: String?
        public let signingCertificateSHA256: String?
        public let certificateExpires: String?
        public let isCertificateExpired: Bool
        public let certificateChainLength: Int?
        public let certificateTrustValid: Bool?
        public let certificateChain: [CertificateDetail]

        public init(
            teamId: String? = nil,
            hardenedRuntime: Bool? = nil,
            libraryValidation: Bool? = nil,
            signed: Bool? = nil,
            analysis: SigningAnalysis = SigningAnalysis(),
            certificate: CertificateState = CertificateState()
        ) {
            self.teamId = teamId
            self.hardenedRuntime = hardenedRuntime
            self.libraryValidation = libraryValidation
            self.signed = signed
            self.codeSigningAnalysisError = analysis.codeSigningAnalysisError
            self.isNotarized = analysis.isNotarized
            self.isAdhocSigned = analysis.isAdhocSigned
            self.signingCertificateCN = certificate.signingCertificateCN
            self.signingCertificateSHA256 = certificate.signingCertificateSHA256
            self.certificateExpires = certificate.certificateExpires
            self.isCertificateExpired = certificate.isCertificateExpired
            self.certificateChainLength = certificate.certificateChainLength
            self.certificateTrustValid = certificate.certificateTrustValid
            self.certificateChain = certificate.certificateChain
        }
    }

    public struct SigningAnalysis: Codable, Sendable {
        public let codeSigningAnalysisError: Bool
        public let isNotarized: Bool?
        public let isAdhocSigned: Bool

        public init(
            codeSigningAnalysisError: Bool = false,
            isNotarized: Bool? = nil,
            isAdhocSigned: Bool = false
        ) {
            self.codeSigningAnalysisError = codeSigningAnalysisError
            self.isNotarized = isNotarized
            self.isAdhocSigned = isAdhocSigned
        }
    }

    public struct CertificateState: Codable, Sendable {
        public let signingCertificateCN: String?
        public let signingCertificateSHA256: String?
        public let certificateExpires: String?
        public let isCertificateExpired: Bool
        public let certificateChainLength: Int?
        public let certificateTrustValid: Bool?
        public let certificateChain: [CertificateDetail]

        public init(
            signingCertificateCN: String? = nil,
            signingCertificateSHA256: String? = nil,
            certificateExpires: String? = nil,
            isCertificateExpired: Bool = false,
            certificateChainLength: Int? = nil,
            certificateTrustValid: Bool? = nil,
            certificateChain: [CertificateDetail] = []
        ) {
            self.signingCertificateCN = signingCertificateCN
            self.signingCertificateSHA256 = signingCertificateSHA256
            self.certificateExpires = certificateExpires
            self.isCertificateExpired = isCertificateExpired
            self.certificateChainLength = certificateChainLength
            self.certificateTrustValid = certificateTrustValid
            self.certificateChain = certificateChain
        }
    }

    public struct Security: Codable, Sendable {
        public let isSipProtected: Bool
        public let isSandboxed: Bool
        public let sandboxExceptions: [String]

        public init(
            isSipProtected: Bool = false,
            isSandboxed: Bool = false,
            sandboxExceptions: [String] = []
        ) {
            self.isSipProtected = isSipProtected
            self.isSandboxed = isSandboxed
            self.sandboxExceptions = sandboxExceptions
        }
    }

    public struct EntitlementState: Codable, Sendable {
        public let entitlementsAvailable: Bool
        public let entitlementExtractionError: String?
        public let entitlements: [EntitlementInfo]
        public let injectionMethods: [InjectionMethod]
        public let launchConstraintCategory: String?

        public init(
            entitlementsAvailable: Bool = true,
            entitlementExtractionError: String? = nil,
            entitlements: [EntitlementInfo] = [],
            injectionMethods: [InjectionMethod] = [],
            launchConstraintCategory: String? = nil
        ) {
            self.entitlementsAvailable = entitlementsAvailable
            self.entitlementExtractionError = entitlementExtractionError
            self.entitlements = entitlements
            self.injectionMethods = injectionMethods
            self.launchConstraintCategory = launchConstraintCategory
        }
    }

    public init(
        identity: Identity,
        flags: Flags,
        signing: Signing = Signing(),
        security: Security = Security(),
        entitlementState: EntitlementState = EntitlementState(),
        sandboxProfile: SandboxProfile? = nil,
        quarantineInfo: QuarantineInfo? = nil
    ) {
        self.name = identity.name
        self.bundleId = identity.bundleId
        self.path = identity.path
        self.version = identity.version
        self.teamId = signing.teamId
        self.hardenedRuntime = signing.hardenedRuntime
        self.libraryValidation = signing.libraryValidation
        self.isElectron = flags.isElectron
        self.isSystem = flags.isSystem
        self.signed = signing.signed
        self.codeSigningAnalysisError = signing.codeSigningAnalysisError
        self.isSipProtected = security.isSipProtected
        self.isSandboxed = security.isSandboxed
        self.sandboxExceptions = security.sandboxExceptions
        self.entitlementsAvailable = entitlementState.entitlementsAvailable
        self.entitlementExtractionError = entitlementState.entitlementExtractionError
        self.signingCertificateCN = signing.signingCertificateCN
        self.signingCertificateSHA256 = signing.signingCertificateSHA256
        self.certificateExpires = signing.certificateExpires
        self.isCertificateExpired = signing.isCertificateExpired
        self.certificateChainLength = signing.certificateChainLength
        self.certificateTrustValid = signing.certificateTrustValid
        self.certificateChain = signing.certificateChain
        self.isNotarized = signing.isNotarized
        self.isAdhocSigned = signing.isAdhocSigned
        self.entitlements = entitlementState.entitlements
        self.injectionMethods = entitlementState.injectionMethods
        self.launchConstraintCategory = entitlementState.launchConstraintCategory
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
        case codeSigningAnalysisError = "code_signing_analysis_error"
        case isSipProtected = "is_sip_protected"
        case isSandboxed = "is_sandboxed"
        case sandboxExceptions = "sandbox_exceptions"
        case entitlementsAvailable = "entitlements_available"
        case entitlementExtractionError = "entitlement_extraction_error"
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
    /// Returns a copy with the supplied analysis states, preserving identity and enrichments.
    public func replacing(
        signing: Signing,
        security: Security,
        entitlementState: EntitlementState
    ) -> Application {
        Application(
            identity: identity,
            flags: flags,
            signing: signing,
            security: security,
            entitlementState: entitlementState,
            sandboxProfile: sandboxProfile,
            quarantineInfo: quarantineInfo
        )
    }

    /// Returns a copy with a different sandboxProfile, preserving all other fields.
    public func with(sandboxProfile newProfile: SandboxProfile?) -> Application {
        Application(
            identity: identity,
            flags: flags,
            signing: signing,
            security: security,
            entitlementState: entitlementState,
            sandboxProfile: newProfile,
            quarantineInfo: quarantineInfo
        )
    }

    /// Returns a copy with different quarantineInfo, preserving all other fields.
    public func with(quarantineInfo newInfo: QuarantineInfo?) -> Application {
        Application(
            identity: identity,
            flags: flags,
            signing: signing,
            security: security,
            entitlementState: entitlementState,
            sandboxProfile: sandboxProfile,
            quarantineInfo: newInfo
        )
    }

    private var identity: Identity {
        Identity(name: name, bundleId: bundleId, path: path, version: version)
    }

    private var flags: Flags {
        Flags(isElectron: isElectron, isSystem: isSystem)
    }

    private var signing: Signing {
        Signing(
            teamId: teamId,
            hardenedRuntime: hardenedRuntime,
            libraryValidation: libraryValidation,
            signed: signed,
            analysis: SigningAnalysis(
                codeSigningAnalysisError: codeSigningAnalysisError,
                isNotarized: isNotarized,
                isAdhocSigned: isAdhocSigned
            ),
            certificate: CertificateState(
                signingCertificateCN: signingCertificateCN,
                signingCertificateSHA256: signingCertificateSHA256,
                certificateExpires: certificateExpires,
                isCertificateExpired: isCertificateExpired,
                certificateChainLength: certificateChainLength,
                certificateTrustValid: certificateTrustValid,
                certificateChain: certificateChain
            )
        )
    }

    private var security: Security {
        Security(
            isSipProtected: isSipProtected,
            isSandboxed: isSandboxed,
            sandboxExceptions: sandboxExceptions
        )
    }

    private var entitlementState: EntitlementState {
        EntitlementState(
            entitlementsAvailable: entitlementsAvailable,
            entitlementExtractionError: entitlementExtractionError,
            entitlements: entitlements,
            injectionMethods: injectionMethods,
            launchConstraintCategory: launchConstraintCategory
        )
    }
}
