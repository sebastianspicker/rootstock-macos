import Foundation

/// Host identity snapshot.
public struct HostState: Codable, Sendable, Equatable {
    public var hostname: String
    public var username: String
    public var osVersion: String
    public var osBuild: String?
    public var arch: String
    public var processArch: String
    public var uptimeSeconds: TimeInterval?
    public var isRoot: Bool

    public init(
        hostname: String,
        username: String,
        osVersion: String,
        osBuild: String? = nil,
        arch: String,
        processArch: String,
        uptimeSeconds: TimeInterval? = nil,
        isRoot: Bool = false
    ) {
        self.hostname = hostname
        self.username = username
        self.osVersion = osVersion
        self.osBuild = osBuild
        self.arch = arch
        self.processArch = processArch
        self.uptimeSeconds = uptimeSeconds
        self.isRoot = isRoot
    }
}

/// Detected security product presence (path/bundle existence only).
public struct SecurityProductHit: Codable, Sendable, Equatable {
    public var name: String
    public var path: String
    public var present: Bool

    public init(name: String, path: String, present: Bool) {
        self.name = name
        self.path = path
        self.present = present
    }
}

/// User LaunchAgent inventory entry.
public struct LaunchAgentEntry: Codable, Sendable, Equatable {
    public var label: String?
    public var path: String
    public var programArguments: [String]

    public init(label: String?, path: String, programArguments: [String] = []) {
        self.label = label
        self.path = path
        self.programArguments = programArguments
    }
}

/// BTM / login-items evidence (no binary format reverse-engineering).
public struct LoginItemsState: Codable, Sendable, Equatable {
    public var btmStorePresent: Bool
    public var btmDirectoryPath: String?
    public var btmDirectorySizeBytes: Int64?
    public var backgroundItemsBtmPath: String?
    public var backgroundItemsBtmSizeBytes: Int64?
    public var loginItemPaths: [String]
    public var notes: [String]

    public init(
        btmStorePresent: Bool = false,
        btmDirectoryPath: String? = nil,
        btmDirectorySizeBytes: Int64? = nil,
        backgroundItemsBtmPath: String? = nil,
        backgroundItemsBtmSizeBytes: Int64? = nil,
        loginItemPaths: [String] = [],
        notes: [String] = []
    ) {
        self.btmStorePresent = btmStorePresent
        self.btmDirectoryPath = btmDirectoryPath
        self.btmDirectorySizeBytes = btmDirectorySizeBytes
        self.backgroundItemsBtmPath = backgroundItemsBtmPath
        self.backgroundItemsBtmSizeBytes = backgroundItemsBtmSizeBytes
        self.loginItemPaths = loginItemPaths
        self.notes = notes
    }
}

/// Browser DB metadata only - never row contents / cookies / passwords.
public struct BrowserMetaEntry: Codable, Sendable, Equatable {
    public var browser: String
    public var kind: String
    public var path: String
    public var exists: Bool
    public var sizeBytes: Int64?
    public var modifiedAt: Date?

    public init(
        browser: String,
        kind: String,
        path: String,
        exists: Bool,
        sizeBytes: Int64? = nil,
        modifiedAt: Date? = nil
    ) {
        self.browser = browser
        self.kind = kind
        self.path = path
        self.exists = exists
        self.sizeBytes = sizeBytes
        self.modifiedAt = modifiedAt
    }
}

/// Codesign / entitlement sample for an app or binary path.
public struct CodesignSample: Codable, Sendable, Equatable {
    public struct Signature: Sendable {
        public var signed: Bool? = nil
        public var identifier: String? = nil
        public var teamIdentifier: String? = nil
        public var hardenedRuntime: Bool? = nil
        public var getTaskAllow: Bool? = nil
        public var disableLibraryValidation: Bool? = nil
        public var allowDyldEnvironmentVariables: Bool? = nil
        public var allowUnsignedExecutableMemory: Bool? = nil

        public init(
            signed: Bool? = nil,
            identifier: String? = nil,
            teamIdentifier: String? = nil,
            hardenedRuntime: Bool? = nil,
            getTaskAllow: Bool? = nil,
            disableLibraryValidation: Bool? = nil,
            allowDyldEnvironmentVariables: Bool? = nil,
            allowUnsignedExecutableMemory: Bool? = nil
        ) {
            self.signed = signed
            self.identifier = identifier
            self.teamIdentifier = teamIdentifier
            self.hardenedRuntime = hardenedRuntime
            self.getTaskAllow = getTaskAllow
            self.disableLibraryValidation = disableLibraryValidation
            self.allowDyldEnvironmentVariables = allowDyldEnvironmentVariables
            self.allowUnsignedExecutableMemory = allowUnsignedExecutableMemory
        }
    }

    public var path: String
    public var signed: Bool?
    public var identifier: String?
    public var teamIdentifier: String?
    public var hardenedRuntime: Bool?
    public var getTaskAllow: Bool?
    public var disableLibraryValidation: Bool?
    public var allowDyldEnvironmentVariables: Bool?
    public var allowUnsignedExecutableMemory: Bool?
    public var notes: [String]

    public init(path: String, signature: Signature = .init(), notes: [String] = []) {
        self.path = path
        self.signed = signature.signed
        self.identifier = signature.identifier
        self.teamIdentifier = signature.teamIdentifier
        self.hardenedRuntime = signature.hardenedRuntime
        self.getTaskAllow = signature.getTaskAllow
        self.disableLibraryValidation = signature.disableLibraryValidation
        self.allowUnsignedExecutableMemory = signature.allowUnsignedExecutableMemory
        self.allowDyldEnvironmentVariables = signature.allowDyldEnvironmentVariables
        self.notes = notes
    }
}

/// Lightweight dylib / load-command risk signal.
public struct DylibRiskHit: Codable, Sendable, Equatable {
    public var path: String
    public var executablePath: String?
    public var weakDylibs: [String]
    public var notes: [String]

    public init(
        path: String,
        executablePath: String? = nil,
        weakDylibs: [String] = [],
        notes: [String] = []
    ) {
        self.path = path
        self.executablePath = executablePath
        self.weakDylibs = weakDylibs
        self.notes = notes
    }
}

/// Injectability surface derived from HR / dangerous entitlements.
public struct InjectabilityHit: Codable, Sendable, Equatable {
    public var path: String
    public var hardenedRuntime: Bool?
    public var getTaskAllow: Bool?
    public var disableLibraryValidation: Bool?
    public var allowDyldEnvironmentVariables: Bool?
    public var allowUnsignedExecutableMemory: Bool?
    public var riskFlags: [String]
    public var notes: [String]

    public init(
        path: String,
        hardenedRuntime: Bool? = nil,
        getTaskAllow: Bool? = nil,
        disableLibraryValidation: Bool? = nil,
        allowDyldEnvironmentVariables: Bool? = nil,
        allowUnsignedExecutableMemory: Bool? = nil,
        riskFlags: [String] = [],
        notes: [String] = []
    ) {
        self.path = path
        self.hardenedRuntime = hardenedRuntime
        self.getTaskAllow = getTaskAllow
        self.disableLibraryValidation = disableLibraryValidation
        self.allowDyldEnvironmentVariables = allowDyldEnvironmentVariables
        self.allowUnsignedExecutableMemory = allowUnsignedExecutableMemory
        self.riskFlags = riskFlags
        self.notes = notes
    }
}

/// TCC / permission probe summary (non-prompting).
public struct TCCState: Codable, Sendable, Equatable {
    public var fullDiskAccessLikely: Bool?
    public var notes: [String]
    public var probeMethod: String
    /// Multi-domain TCC graph signals (e.g. `ScreenCapture=likely`, `Accessibility=unknown`).
    /// Presence/absence heuristics only - never dumps TCC.db rows or forces prompts.
    public var domainSignals: [String]

    public init(
        fullDiskAccessLikely: Bool? = nil,
        notes: [String] = [],
        probeMethod: String = "stub",
        domainSignals: [String] = []
    ) {
        self.fullDiskAccessLikely = fullDiskAccessLikely
        self.notes = notes
        self.probeMethod = probeMethod
        self.domainSignals = domainSignals
    }
}

/// Endpoint Security / system-extension sensor posture (path heuristics only).
public struct ESFPostureState: Codable, Sendable, Equatable {
    /// Whether EndpointSecurity.framework / ES-related support paths are present.
    public var frameworkPresent: Bool?
    /// Paths that look like ES clients, EDR system extensions, or ES tooling.
    public var clientPaths: [String]
    /// Count of system-extension paths observed (may be filled from sibling collector merge).
    public var systemExtensionCount: Int
    /// Vendor/product hints inferred from path names (not process injection).
    public var edrHints: [String]
    public var notes: [String]

    public init(
        frameworkPresent: Bool? = nil,
        clientPaths: [String] = [],
        systemExtensionCount: Int = 0,
        edrHints: [String] = [],
        notes: [String] = []
    ) {
        self.frameworkPresent = frameworkPresent
        self.clientPaths = clientPaths
        self.systemExtensionCount = systemExtensionCount
        self.edrHints = edrHints
        self.notes = notes
    }
}

/// OS patch-debt / Software Update heuristics for CVE suggester context (not an exploit pack).
public struct PatchDebtState: Codable, Sendable, Equatable {
    public var osVersion: String?
    public var osBuild: String?
    public var softwareUpdatePlistPresent: Bool?
    /// Opaque install-history / SUS presence notes (no private package dump).
    public var lastUpdateHints: [String]
    /// Heuristic major-version lag vs a conservative known-current baseline (nil = unknown).
    public var majorVersionLag: Int?
    public var notes: [String]

    public init(
        osVersion: String? = nil,
        osBuild: String? = nil,
        softwareUpdatePlistPresent: Bool? = nil,
        lastUpdateHints: [String] = [],
        majorVersionLag: Int? = nil,
        notes: [String] = []
    ) {
        self.osVersion = osVersion
        self.osBuild = osBuild
        self.softwareUpdatePlistPresent = softwareUpdatePlistPresent
        self.lastUpdateHints = lastUpdateHints
        self.majorVersionLag = majorVersionLag
        self.notes = notes
    }
}

/// Launch-constraint / library-validation injectability truth notes.
public struct LaunchConstraintState: Codable, Sendable, Equatable {
    /// Paths where launch-constraint / constraint-ish plists or codesign notes were observed.
    public var constrainedPaths: [String]
    /// Paths with dangerous entitlement / HR composite without constraint evidence.
    public var unconstrainedRiskPaths: [String]
    public var notes: [String]

    public init(
        constrainedPaths: [String] = [],
        unconstrainedRiskPaths: [String] = [],
        notes: [String] = []
    ) {
        self.constrainedPaths = constrainedPaths
        self.unconstrainedRiskPaths = unconstrainedRiskPaths
        self.notes = notes
    }
}

/// NetworkExtension / VPN / content-filter posture (path heuristics only).
public struct NetworkExtensionState: Codable, Sendable, Equatable {
    public var frameworkPresent: Bool?
    public var vpnConfigPaths: [String]
    public var contentFilterHints: [String]
    public var packetTunnelHints: [String]
    public var neAppPaths: [String]
    public var notes: [String]

    public init(
        frameworkPresent: Bool? = nil,
        vpnConfigPaths: [String] = [],
        contentFilterHints: [String] = [],
        packetTunnelHints: [String] = [],
        neAppPaths: [String] = [],
        notes: [String] = []
    ) {
        self.frameworkPresent = frameworkPresent
        self.vpnConfigPaths = vpnConfigPaths
        self.contentFilterHints = contentFilterHints
        self.packetTunnelHints = packetTunnelHints
        self.neAppPaths = neAppPaths
        self.notes = notes
    }
}

/// Authorization rights / auth.db / packagekit privilege surface (path only).
public struct AuthRightsState: Codable, Sendable, Equatable {
    public var authDbPresent: Bool?
    public var authDbPath: String?
    public var authorizationPlistPaths: [String]
    public var packageKitPaths: [String]
    public var rightsHintCount: Int
    public var notes: [String]

    public init(
        authDbPresent: Bool? = nil,
        authDbPath: String? = nil,
        authorizationPlistPaths: [String] = [],
        packageKitPaths: [String] = [],
        rightsHintCount: Int = 0,
        notes: [String] = []
    ) {
        self.authDbPresent = authDbPresent
        self.authDbPath = authDbPath
        self.authorizationPlistPaths = authorizationPlistPaths
        self.packageKitPaths = packageKitPaths
        self.rightsHintCount = rightsHintCount
        self.notes = notes
    }
}

/// Developer toolchain dual-use inventory (path presence only).
public struct DeveloperToolchainState: Codable, Sendable, Equatable {
    public var xcodePresent: Bool?
    public var commandLineToolsPresent: Bool?
    /// Xcode / CLT / SDK root paths observed.
    public var toolchainPaths: [String]
    /// Dual-use bins (lldb, dtrace, codesign, otool, nm, …) path inventory.
    public var dualUseBinaries: [String]
    public var notes: [String]

    public init(
        xcodePresent: Bool? = nil,
        commandLineToolsPresent: Bool? = nil,
        toolchainPaths: [String] = [],
        dualUseBinaries: [String] = [],
        notes: [String] = []
    ) {
        self.xcodePresent = xcodePresent
        self.commandLineToolsPresent = commandLineToolsPresent
        self.toolchainPaths = toolchainPaths
        self.dualUseBinaries = dualUseBinaries
        self.notes = notes
    }
}

/// Time Machine / local snapshot data-access surface (no backup dump).
public struct TimeMachineState: Codable, Sendable, Equatable {
    public var preferencesPresent: Bool?
    /// Backup destination / TM machine-dir path hints.
    public var backupPaths: [String]
    /// Local snapshot volume / `.localsnapshots` hints.
    public var localSnapshotHints: [String]
    /// Mounted TM / backup volume path hints.
    public var volumeMountHints: [String]
    public var notes: [String]

    public init(
        preferencesPresent: Bool? = nil,
        backupPaths: [String] = [],
        localSnapshotHints: [String] = [],
        volumeMountHints: [String] = [],
        notes: [String] = []
    ) {
        self.preferencesPresent = preferencesPresent
        self.backupPaths = backupPaths
        self.localSnapshotHints = localSnapshotHints
        self.volumeMountHints = volumeMountHints
        self.notes = notes
    }
}

/// User-space mobileconfig / profile sideload surface (no profile payload dump).
public struct ConfigProfileSideloadState: Codable, Sendable, Equatable {
    /// User-owned `.mobileconfig` paths (e.g. Desktop/Documents).
    public var userMobileconfigPaths: [String]
    /// Downloads / browser-drop profile path hints.
    public var downloadsProfileHints: [String]
    /// Whether a system profile-install DB / store path was observed.
    public var profileInstallDbPresent: Bool?
    public var notes: [String]

    public init(
        userMobileconfigPaths: [String] = [],
        downloadsProfileHints: [String] = [],
        profileInstallDbPresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.userMobileconfigPaths = userMobileconfigPaths
        self.downloadsProfileHints = downloadsProfileHints
        self.profileInstallDbPresent = profileInstallDbPresent
        self.notes = notes
    }
}
