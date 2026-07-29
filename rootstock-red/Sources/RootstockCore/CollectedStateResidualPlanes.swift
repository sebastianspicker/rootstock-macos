import Foundation

// MARK: - Wave-15 2026 coverage multi-plane surfaces


/// Photos.app library collection path plane (never reads photo contents or exports Photo Library media).
public struct PhotosLibraryPathState: Codable, Sendable, Equatable {
    public var photosAppPaths: [String]
    public var photosLibraryPaths: [String]
    public var photosSupportPaths: [String]
    public var photosSurfacePresent: Bool?
    public var notes: [String]
    public init(
        photosAppPaths: [String] = [],
        photosLibraryPaths: [String] = [],
        photosSupportPaths: [String] = [],
        photosSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.photosAppPaths = photosAppPaths
        self.photosLibraryPaths = photosLibraryPaths
        self.photosSupportPaths = photosSupportPaths
        self.photosSurfacePresent = photosSurfacePresent
        self.notes = notes
    }
}


/// VPN configuration dual-use residual surface (never installs VPN profiles or rewrites network extension VPN configs).
public struct VpnConfigDualuseState: Codable, Sendable, Equatable {
    public var vpnFrameworkPaths: [String]
    public var vpnPrefPaths: [String]
    public var vpnToolPaths: [String]
    public var vpnSurfacePresent: Bool?
    public var notes: [String]
    public init(
        vpnFrameworkPaths: [String] = [],
        vpnPrefPaths: [String] = [],
        vpnToolPaths: [String] = [],
        vpnSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.vpnFrameworkPaths = vpnFrameworkPaths
        self.vpnPrefPaths = vpnPrefPaths
        self.vpnToolPaths = vpnToolPaths
        self.vpnSurfacePresent = vpnSurfacePresent
        self.notes = notes
    }
}


/// App sandbox container residual depth (never breaks app sandbox or forges container entitlements).
public struct SandboxContainerDepthState: Codable, Sendable, Equatable {
    public var containerRootPaths: [String]
    public var sandboxProfilePaths: [String]
    public var seatbeltSupportPaths: [String]
    public var sandboxSurfacePresent: Bool?
    public var notes: [String]
    public init(
        containerRootPaths: [String] = [],
        sandboxProfilePaths: [String] = [],
        seatbeltSupportPaths: [String] = [],
        sandboxSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.containerRootPaths = containerRootPaths
        self.sandboxProfilePaths = sandboxProfilePaths
        self.seatbeltSupportPaths = seatbeltSupportPaths
        self.sandboxSurfacePresent = sandboxSurfacePresent
        self.notes = notes
    }
}


/// XPC Mach service residual depth (never registers XPC services or injects into Mach ports).
public struct XpcMachServiceDepthState: Codable, Sendable, Equatable {
    public var xpcBootstrapPaths: [String]
    public var machServicePlistPaths: [String]
    public var xpcToolPaths: [String]
    public var xpcMachSurfacePresent: Bool?
    public var notes: [String]
    public init(
        xpcBootstrapPaths: [String] = [],
        machServicePlistPaths: [String] = [],
        xpcToolPaths: [String] = [],
        xpcMachSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.xpcBootstrapPaths = xpcBootstrapPaths
        self.machServicePlistPaths = machServicePlistPaths
        self.xpcToolPaths = xpcToolPaths
        self.xpcMachSurfacePresent = xpcMachSurfacePresent
        self.notes = notes
    }
}


/// Time Machine local snapshot residual depth (never mounts snapshots for data theft or deletes backup catalogs).
public struct TmLocalSnapshotDepthState: Codable, Sendable, Equatable {
    public var tmUtilPaths: [String]
    public var snapshotStorePaths: [String]
    public var tmPrefPaths: [String]
    public var tmSnapshotSurfacePresent: Bool?
    public var notes: [String]
    public init(
        tmUtilPaths: [String] = [],
        snapshotStorePaths: [String] = [],
        tmPrefPaths: [String] = [],
        tmSnapshotSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.tmUtilPaths = tmUtilPaths
        self.snapshotStorePaths = snapshotStorePaths
        self.tmPrefPaths = tmPrefPaths
        self.tmSnapshotSurfacePresent = tmSnapshotSurfacePresent
        self.notes = notes
    }
}


/// Emond legacy rules residual depth (never installs emond rules or enables the legacy event monitor daemon).
public struct EmondLegacyDepthState: Codable, Sendable, Equatable {
    public var emondBinaryPaths: [String]
    public var emondRulePaths: [String]
    public var emondSupportPaths: [String]
    public var emondSurfacePresent: Bool?
    public var notes: [String]
    public init(
        emondBinaryPaths: [String] = [],
        emondRulePaths: [String] = [],
        emondSupportPaths: [String] = [],
        emondSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.emondBinaryPaths = emondBinaryPaths
        self.emondRulePaths = emondRulePaths
        self.emondSupportPaths = emondSupportPaths
        self.emondSurfacePresent = emondSurfacePresent
        self.notes = notes
    }
}


/// Screen Sharing / ARD residual depth (never enables Screen Sharing or ARD, never connects to remote desktops).
public struct ScreenSharingArdDepthState: Codable, Sendable, Equatable {
    public var screenSharingAppPaths: [String]
    public var ardAgentPaths: [String]
    public var remoteMgmtPrefPaths: [String]
    public var ardSurfacePresent: Bool?
    public var notes: [String]
    public init(
        screenSharingAppPaths: [String] = [],
        ardAgentPaths: [String] = [],
        remoteMgmtPrefPaths: [String] = [],
        ardSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.screenSharingAppPaths = screenSharingAppPaths
        self.ardAgentPaths = ardAgentPaths
        self.remoteMgmtPrefPaths = remoteMgmtPrefPaths
        self.ardSurfacePresent = ardSurfacePresent
        self.notes = notes
    }
}


/// Keychain ACL path residual surface (never dumps keychain items, passwords, or private keys).
public struct KeychainAclPathState: Codable, Sendable, Equatable {
    public var keychainDbPaths: [String]
    public var securityToolPaths: [String]
    public var keychainSupportPaths: [String]
    public var keychainAclSurfacePresent: Bool?
    public var notes: [String]
    public init(
        keychainDbPaths: [String] = [],
        securityToolPaths: [String] = [],
        keychainSupportPaths: [String] = [],
        keychainAclSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.keychainDbPaths = keychainDbPaths
        self.securityToolPaths = securityToolPaths
        self.keychainSupportPaths = keychainSupportPaths
        self.keychainAclSurfacePresent = keychainAclSurfacePresent
        self.notes = notes
    }
}


/// Python runtime dual-use residual surface (never executes third-party Python payloads or drops malicious site-packages).
public struct PythonRuntimeDualuseState: Codable, Sendable, Equatable {
    public var pythonBinaryPaths: [String]
    public var sitePackagePaths: [String]
    public var pythonFrameworkPaths: [String]
    public var pythonSurfacePresent: Bool?
    public var notes: [String]
    public init(
        pythonBinaryPaths: [String] = [],
        sitePackagePaths: [String] = [],
        pythonFrameworkPaths: [String] = [],
        pythonSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.pythonBinaryPaths = pythonBinaryPaths
        self.sitePackagePaths = sitePackagePaths
        self.pythonFrameworkPaths = pythonFrameworkPaths
        self.pythonSurfacePresent = pythonSurfacePresent
        self.notes = notes
    }
}


/// Shell plugin manager dual-use residual (never installs oh-my-zsh plugins or rewrites shell init for persistence).
public struct ShellPluginManagerState: Codable, Sendable, Equatable {
    public var omzPaths: [String]
    public var pluginDirPaths: [String]
    public var shellInitPaths: [String]
    public var shellPluginSurfacePresent: Bool?
    public var notes: [String]
    public init(
        omzPaths: [String] = [],
        pluginDirPaths: [String] = [],
        shellInitPaths: [String] = [],
        shellPluginSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.omzPaths = omzPaths
        self.pluginDirPaths = pluginDirPaths
        self.shellInitPaths = shellInitPaths
        self.shellPluginSurfacePresent = shellPluginSurfacePresent
        self.notes = notes
    }
}
