import Foundation

// MARK: - state types

/// App sandbox / entitlement thick-client inventory (no entitlement mutation).
public struct AppSandboxEntitlementState: Codable, Sendable, Equatable {
    /// Sample app paths inspected for sandbox/entitlement posture.
    public var appSamples: [String]
    /// Paths or labels indicating app-sandbox entitlement present.
    public var sandboxedHints: [String]
    /// Paths or labels with dangerous entitlement class (get-task-allow, disable-library-validation, etc.).
    public var dangerousEntitlementHints: [String]
    /// Unsandboxed or hardened-runtime-off thick-client samples.
    public var unsandboxedRiskPaths: [String]
    public var notes: [String]

    public init(
        appSamples: [String] = [],
        sandboxedHints: [String] = [],
        dangerousEntitlementHints: [String] = [],
        unsandboxedRiskPaths: [String] = [],
        notes: [String] = []
    ) {
        self.appSamples = appSamples
        self.sandboxedHints = sandboxedHints
        self.dangerousEntitlementHints = dangerousEntitlementHints
        self.unsandboxedRiskPaths = unsandboxedRiskPaths
        self.notes = notes
    }
}

/// Notarization / stapling trust-depth surface (no ticket forgery).
public struct NotarizationStaplingState: Codable, Sendable, Equatable {
    /// Notarization/stapling tooling paths present (stapler, spctl, etc.).
    public var toolingPaths: [String]
    /// Ticket/cache path hints when listable.
    public var ticketCacheHints: [String]
    /// App samples lacking team ID / ad-hoc / unstapled class signals.
    public var unstapledOrAdHocHints: [String]
    /// Whether notarization assessment tooling appears available.
    public var assessmentToolsPresent: Bool?
    public var notes: [String]

    public init(
        toolingPaths: [String] = [],
        ticketCacheHints: [String] = [],
        unstapledOrAdHocHints: [String] = [],
        assessmentToolsPresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.toolingPaths = toolingPaths
        self.ticketCacheHints = ticketCacheHints
        self.unstapledOrAdHocHints = unstapledOrAdHocHints
        self.assessmentToolsPresent = assessmentToolsPresent
        self.notes = notes
    }
}

/// Virtualization / container dual-use surface (no container start / secret harvest).
public struct VirtualizationContainerState: Codable, Sendable, Equatable {
    /// Docker / Colima / Lima / OrbStack / podman path hits.
    public var containerToolPaths: [String]
    /// UTM / Parallels / VMware / VirtualBox / multipass app paths.
    public var hypervisorAppPaths: [String]
    /// Virtualization.framework / related framework path hints.
    public var frameworkPaths: [String]
    /// Whether any virt/container dual-use tooling was observed.
    public var dualUsePresent: Bool?
    public var notes: [String]

    public init(
        containerToolPaths: [String] = [],
        hypervisorAppPaths: [String] = [],
        frameworkPaths: [String] = [],
        dualUsePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.containerToolPaths = containerToolPaths
        self.hypervisorAppPaths = hypervisorAppPaths
        self.frameworkPaths = frameworkPaths
        self.dualUsePresent = dualUsePresent
        self.notes = notes
    }
}

/// Continuity / AirDrop proximity transfer posture (no pasteboard / payload abuse).
public struct ContinuityAirDropState: Codable, Sendable, Equatable {
    /// Preference / domain path hints for AirDrop / sharing.
    public var airdropPrefPaths: [String]
    /// Continuity / Handoff framework or support path hints.
    public var continuityFrameworkPaths: [String]
    /// Bluetooth / nearby-sharing adjacency path hints (presence only).
    public var nearbyShareHints: [String]
    /// Whether a proximity-transfer surface was observed.
    public var proximitySurfacePresent: Bool?
    public var notes: [String]

    public init(
        airdropPrefPaths: [String] = [],
        continuityFrameworkPaths: [String] = [],
        nearbyShareHints: [String] = [],
        proximitySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.airdropPrefPaths = airdropPrefPaths
        self.continuityFrameworkPaths = continuityFrameworkPaths
        self.nearbyShareHints = nearbyShareHints
        self.proximitySurfacePresent = proximitySurfacePresent
        self.notes = notes
    }
}

/// FileVault / recovery escrow posture (never recovery-key material).
public struct FileVaultEscrowState: Codable, Sendable, Equatable {
    /// FileVault on/off when known (may mirror ProtectionsState).
    public var fileVaultOn: Bool?
    /// Escrow / recovery preference or support path hints (paths only).
    public var escrowPathHints: [String]
    /// MDM / institutional recovery artifact path hints.
    public var institutionalEscrowHints: [String]
    /// fdesetup / related tooling path presence.
    public var fdesetupPresent: Bool?
    public var notes: [String]

    public init(
        fileVaultOn: Bool? = nil,
        escrowPathHints: [String] = [],
        institutionalEscrowHints: [String] = [],
        fdesetupPresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.fileVaultOn = fileVaultOn
        self.escrowPathHints = escrowPathHints
        self.institutionalEscrowHints = institutionalEscrowHints
        self.fdesetupPresent = fdesetupPresent
        self.notes = notes
    }
}

// MARK: - Wave-8 2026 coverage residual surfaces

/// ClickFix / paste-and-run Terminal delivery posture (never builds lures/payloads).
public struct ClickFixTerminalDeliveryState: Codable, Sendable, Equatable {
    /// Terminal.app / shell path hits used for paste-run delivery class.
    public var terminalAppPaths: [String]
    /// Script Editor / AppleScript URL-scheme adjacent path hits.
    public var scriptEditorPaths: [String]
    /// Dual-use loader binaries (curl, osascript, sh, zsh, bash) path hits.
    public var loaderBinaryPaths: [String]
    /// Paste-warning / Terminal security preference path hints when listable.
    public var pasteWarningHints: [String]
    /// Whether a paste-run delivery surface was observed.
    public var deliverySurfacePresent: Bool?
    public var notes: [String]

    public init(
        terminalAppPaths: [String] = [],
        scriptEditorPaths: [String] = [],
        loaderBinaryPaths: [String] = [],
        pasteWarningHints: [String] = [],
        deliverySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.terminalAppPaths = terminalAppPaths
        self.scriptEditorPaths = scriptEditorPaths
        self.loaderBinaryPaths = loaderBinaryPaths
        self.pasteWarningHints = pasteWarningHints
        self.deliverySurfacePresent = deliverySurfacePresent
        self.notes = notes
    }
}

/// Remote Apple Events / EPPC / Automation lateral posture (never enables RAE or sends AE).
public struct RemoteAppleEventsState: Codable, Sendable, Equatable {
    /// Preference / Sharing path hints for Remote Apple Events.
    public var remoteAEPrefPaths: [String]
    /// EPPC / AppleEvents framework or support path hints.
    public var eppcFrameworkPaths: [String]
    /// ARD / remote management adjacency path hints.
    public var remoteMgmtHints: [String]
    /// Whether a remote-automation lateral surface was observed.
    public var remoteAutomationSurfacePresent: Bool?
    public var notes: [String]

    public init(
        remoteAEPrefPaths: [String] = [],
        eppcFrameworkPaths: [String] = [],
        remoteMgmtHints: [String] = [],
        remoteAutomationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.remoteAEPrefPaths = remoteAEPrefPaths
        self.eppcFrameworkPaths = eppcFrameworkPaths
        self.remoteMgmtHints = remoteMgmtHints
        self.remoteAutomationSurfacePresent = remoteAutomationSurfacePresent
        self.notes = notes
    }
}

/// Spotlight / mdworker / on-device AI-cache data-access class (never dumps index/cache contents).
public struct SpotlightAICacheState: Codable, Sendable, Equatable {
    /// Spotlight / mds / mdworker binary and store path hits.
    public var spotlightPaths: [String]
    /// CoreSpotlight / metadata framework path hits.
    public var metadataFrameworkPaths: [String]
    /// On-device AI / Apple Intelligence–class cache directory path hints (presence only).
    public var aiCachePathHints: [String]
    /// Whether an index/cache data-access surface was observed.
    public var dataAccessSurfacePresent: Bool?
    public var notes: [String]

    public init(
        spotlightPaths: [String] = [],
        metadataFrameworkPaths: [String] = [],
        aiCachePathHints: [String] = [],
        dataAccessSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.spotlightPaths = spotlightPaths
        self.metadataFrameworkPaths = metadataFrameworkPaths
        self.aiCachePathHints = aiCachePathHints
        self.dataAccessSurfacePresent = dataAccessSurfacePresent
        self.notes = notes
    }
}

/// Security-product management-plane / privileged-XPC unload class (never unloads sensors).
public struct SecurityMgmtPlaneState: Codable, Sendable, Equatable {
    /// Management CLI / systemextensionsctl / vendor uninstaller path hits.
    public var managementCLIPaths: [String]
    /// Privileged helper tools associated with security products (paths only).
    public var privilegedHelperPaths: [String]
    /// Uninstall / unload adjacency path hints.
    public var unloadAdjacentHints: [String]
    /// Whether a management-plane surface was observed.
    public var managementPlanePresent: Bool?
    public var notes: [String]

    public init(
        managementCLIPaths: [String] = [],
        privilegedHelperPaths: [String] = [],
        unloadAdjacentHints: [String] = [],
        managementPlanePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.managementCLIPaths = managementCLIPaths
        self.privilegedHelperPaths = privilegedHelperPaths
        self.unloadAdjacentHints = unloadAdjacentHints
        self.managementPlanePresent = managementPlanePresent
        self.notes = notes
    }
}

/// Third-party TCC-inheritance / embedded-interpreter class (never forges TCC grants).
public struct ThirdPartyTCCInheritanceState: Codable, Sendable, Equatable {
    /// High-value thick-client app paths sampled for inheritance class.
    public var thickClientAppPaths: [String]
    /// Embedded interpreter path hits (Node/Python/Ruby inside apps).
    public var embeddedInterpreterPaths: [String]
    /// Electron / CEF / helper path hits.
    public var electronHelperPaths: [String]
    /// Whether a TCC-inheritance surface was observed.
    public var inheritanceSurfacePresent: Bool?
    public var notes: [String]

    public init(
        thickClientAppPaths: [String] = [],
        embeddedInterpreterPaths: [String] = [],
        electronHelperPaths: [String] = [],
        inheritanceSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.thickClientAppPaths = thickClientAppPaths
        self.embeddedInterpreterPaths = embeddedInterpreterPaths
        self.electronHelperPaths = electronHelperPaths
        self.inheritanceSurfacePresent = inheritanceSurfacePresent
        self.notes = notes
    }
}

/// SSH-agent / key path lateral posture depth (never reads key material).
public struct SSHAgentKeyPathState: Codable, Sendable, Equatable {
    /// ssh-agent socket / agent plist path hits.
    public var agentSocketPaths: [String]
    /// authorized_keys / known_hosts / config path hits (paths only).
    public var keyPathHits: [String]
    /// sshd / OpenSSH support path hits.
    public var sshdSupportPaths: [String]
    /// Whether an SSH agent/key path lateral surface was observed.
    public var lateralPathSurfacePresent: Bool?
    public var notes: [String]

    public init(
        agentSocketPaths: [String] = [],
        keyPathHits: [String] = [],
        sshdSupportPaths: [String] = [],
        lateralPathSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.agentSocketPaths = agentSocketPaths
        self.keyPathHits = keyPathHits
        self.sshdSupportPaths = sshdSupportPaths
        self.lateralPathSurfacePresent = lateralPathSurfacePresent
        self.notes = notes
    }
}

// MARK: - Wave-9 2026 coverage residual surfaces

/// PackageKit installer design-based persistence posture (never builds pkgs or invokes installd).
public struct PackageKitInstallerDesignState: Codable, Sendable, Equatable {
    /// package_script_service / installd / system_installd path hits.
    public var installerServicePaths: [String]
    /// InstallerSandboxes / receipt DB / InstallHistory path hits.
    public var receiptAndHistoryPaths: [String]
    /// Installer Plugins path hits.
    public var installerPluginPaths: [String]
    /// pkgutil / installer / PackageKit tooling path hits.
    public var toolingPaths: [String]
    /// Whether an installer design surface was observed.
    public var designSurfacePresent: Bool?
    public var notes: [String]

    public init(
        installerServicePaths: [String] = [],
        receiptAndHistoryPaths: [String] = [],
        installerPluginPaths: [String] = [],
        toolingPaths: [String] = [],
        designSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.installerServicePaths = installerServicePaths
        self.receiptAndHistoryPaths = receiptAndHistoryPaths
        self.installerPluginPaths = installerPluginPaths
        self.toolingPaths = toolingPaths
        self.designSurfacePresent = designSurfacePresent
        self.notes = notes
    }
}

/// Archive / quarantine third-party extractor surface (never strips quarantine or crafts bypass archives).
public struct ArchiveQuarantineExtractorState: Codable, Sendable, Equatable {
    /// Third-party extractor app path hits (The Unarchiver, Keka, etc.).
    public var thirdPartyExtractorPaths: [String]
    /// Stock Archive Utility / ditto / tar path hits.
    public var stockExtractorPaths: [String]
    /// Downloads / archive drop path hints.
    public var archiveDropHints: [String]
    /// Whether an extractor surface was observed.
    public var extractorSurfacePresent: Bool?
    public var notes: [String]

    public init(
        thirdPartyExtractorPaths: [String] = [],
        stockExtractorPaths: [String] = [],
        archiveDropHints: [String] = [],
        extractorSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.thirdPartyExtractorPaths = thirdPartyExtractorPaths
        self.stockExtractorPaths = stockExtractorPaths
        self.archiveDropHints = archiveDropHints
        self.extractorSurfacePresent = extractorSurfacePresent
        self.notes = notes
    }
}

/// Info-stealer multi-app collection path plane (never dumps secrets/cookies/wallets).
public struct InfoStealerPathPlaneState: Codable, Sendable, Equatable {
    /// Browser-adjacent high-value path hits (beyond browser meta reuse).
    public var browserAdjacentPaths: [String]
    /// Mail / Messages / Notes / password-manager path hits.
    public var messagingAndVaultPaths: [String]
    /// Crypto wallet / cloud sync / Desktop-Documents scoop path hits.
    public var walletAndSyncPaths: [String]
    /// Whether a multi-app stealer collection surface was observed.
    public var collectionSurfacePresent: Bool?
    public var notes: [String]

    public init(
        browserAdjacentPaths: [String] = [],
        messagingAndVaultPaths: [String] = [],
        walletAndSyncPaths: [String] = [],
        collectionSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.browserAdjacentPaths = browserAdjacentPaths
        self.messagingAndVaultPaths = messagingAndVaultPaths
        self.walletAndSyncPaths = walletAndSyncPaths
        self.collectionSurfacePresent = collectionSurfacePresent
        self.notes = notes
    }
}

/// TCC / ESF visibility-depth posture (never dumps TCC.db rows or live-subscribes ESF without ROE).
public struct TCCESFVisibilityDepthState: Codable, Sendable, Equatable {
    /// TCC.db / TCC support path hits with listability flags encoded in notes.
    public var tccDbPathHits: [String]
    /// eslogger / log / unified-logging tooling path hits.
    public var visibilityToolPaths: [String]
    /// Privacy / logging preference path hits.
    public var privacyPrefPaths: [String]
    /// Heuristic depth label: strong / partial / thin.
    public var visibilityDepth: String?
    /// Whether a visibility-depth surface was observed.
    public var visibilitySurfacePresent: Bool?
    public var notes: [String]

    public init(
        tccDbPathHits: [String] = [],
        visibilityToolPaths: [String] = [],
        privacyPrefPaths: [String] = [],
        visibilityDepth: String? = nil,
        visibilitySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.tccDbPathHits = tccDbPathHits
        self.visibilityToolPaths = visibilityToolPaths
        self.privacyPrefPaths = privacyPrefPaths
        self.visibilityDepth = visibilityDepth
        self.visibilitySurfacePresent = visibilitySurfacePresent
        self.notes = notes
    }
}

/// MDM profile shallow parse depth (PayloadType inventory only - never dumps secrets).
public struct MDMProfileParseDepthState: Codable, Sendable, Equatable {
    /// Paths of listable `.mobileconfig` / profile plists examined.
    public var examinedProfilePaths: [String]
    /// Distinct PayloadType strings observed (shallow).
    public var payloadTypes: [String]
    /// Count of profiles successfully shallow-parsed.
    public var parsedProfileCount: Int
    /// Whether any PayloadDisplayName keys were present (boolean class).
    public var displayNamePresent: Bool?
    /// Whether a parse-depth surface was observed.
    public var parseSurfacePresent: Bool?
    public var notes: [String]

    public init(
        examinedProfilePaths: [String] = [],
        payloadTypes: [String] = [],
        parsedProfileCount: Int = 0,
        displayNamePresent: Bool? = nil,
        parseSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.examinedProfilePaths = examinedProfilePaths
        self.payloadTypes = payloadTypes
        self.parsedProfileCount = parsedProfileCount
        self.displayNamePresent = displayNamePresent
        self.parseSurfacePresent = parseSurfacePresent
        self.notes = notes
    }
}
