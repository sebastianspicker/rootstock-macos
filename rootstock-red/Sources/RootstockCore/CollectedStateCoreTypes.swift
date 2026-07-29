import Foundation

/// Credential path presence only - never secret material.
public struct CredPathHit: Codable, Sendable, Equatable {
    public var kind: String
    public var path: String
    public var exists: Bool

    public init(kind: String, path: String, exists: Bool) {
        self.kind = kind
        self.path = path
        self.exists = exists
    }
}

/// LOOBin inventory hit.
public struct LOOBinHit: Codable, Sendable, Equatable {
    public var name: String
    public var path: String
    public var present: Bool
    public var tactics: [String]

    public init(name: String, path: String, present: Bool, tactics: [String] = []) {
        self.name = name
        self.path = path
        self.present = present
        self.tactics = tactics
    }
}

/// Running application summary (NSWorkspace-level).
public struct RunningAppInfo: Codable, Sendable, Equatable {
    public var name: String
    public var bundleIdentifier: String?
    public var path: String?

    public init(name: String, bundleIdentifier: String? = nil, path: String? = nil) {
        self.name = name
        self.bundleIdentifier = bundleIdentifier
        self.path = path
    }
}

/// MDM / management posture (path + profile-store heuristics; no payload secrets).
public struct MDMState: Codable, Sendable, Equatable {
    public var enrolled: Bool?
    public var vendorHints: [String]
    /// Top-level filenames under `/Library/Managed Preferences/` (presence only).
    public var managedPreferenceNames: [String]
    /// Whether a configuration-profile store directory was readable.
    public var profileStoreReadable: Bool?
    /// Count of mobileconfig-like / profile files when the store is listable.
    public var profileFileCount: Int?
    /// Presence of PPPC / TCC configuration-profile policy plist (path only).
    public var pppcPolicyPresent: Bool?
    public var notes: [String]

    public init(
        enrolled: Bool? = nil,
        vendorHints: [String] = [],
        managedPreferenceNames: [String] = [],
        profileStoreReadable: Bool? = nil,
        profileFileCount: Int? = nil,
        pppcPolicyPresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.enrolled = enrolled
        self.vendorHints = vendorHints
        self.managedPreferenceNames = managedPreferenceNames
        self.profileStoreReadable = profileStoreReadable
        self.profileFileCount = profileFileCount
        self.pppcPolicyPresent = pppcPolicyPresent
        self.notes = notes
    }
}

/// Identity posture (AD bind / Platform SSO) via filesystem heuristics.
public struct IdentityState: Codable, Sendable, Equatable {
    public var adBound: Bool?
    public var platformSSO: Bool?
    /// Kerberos config present (`edu.mit.Kerberos` prefs and/or `/etc/krb5.conf`).
    public var kerberosConfigPresent: Bool?
    /// Open Directory / DirectoryService config paths observed.
    public var odConfigPaths: [String]
    /// Platform SSO / AppSSO support paths observed.
    public var ssoPaths: [String]
    public var notes: [String]

    public init(
        adBound: Bool? = nil,
        platformSSO: Bool? = nil,
        kerberosConfigPresent: Bool? = nil,
        odConfigPaths: [String] = [],
        ssoPaths: [String] = [],
        notes: [String] = []
    ) {
        self.adBound = adBound
        self.platformSSO = platformSSO
        self.kerberosConfigPresent = kerberosConfigPresent
        self.odConfigPaths = odConfigPaths
        self.ssoPaths = ssoPaths
        self.notes = notes
    }
}

/// Ranked LOOBin plan entry for assess discovery/persist/execute planning.
public struct LOLPlanEntry: Codable, Sendable, Equatable {
    public var name: String
    public var path: String
    public var goal: String
    /// 0–100; higher = noisier / more OPSEC risk.
    public var noiseScore: Int
    public var tccImpact: [String]
    public var rankReason: String

    public init(
        name: String,
        path: String,
        goal: String,
        noiseScore: Int,
        tccImpact: [String] = [],
        rankReason: String = ""
    ) {
        self.name = name
        self.path = path
        self.goal = goal
        self.noiseScore = noiseScore
        self.tccImpact = tccImpact
        self.rankReason = rankReason
    }
}

/// Protections snapshot (SIP / Gatekeeper / FileVault - may be partial).
public struct ProtectionsState: Codable, Sendable, Equatable {
    public var sipEnabled: Bool?
    public var gatekeeperEnabled: Bool?
    public var fileVaultOn: Bool?
    public var notes: [String]

    public init(
        sipEnabled: Bool? = nil,
        gatekeeperEnabled: Bool? = nil,
        fileVaultOn: Bool? = nil,
        notes: [String] = []
    ) {
        self.sipEnabled = sipEnabled
        self.gatekeeperEnabled = gatekeeperEnabled
        self.fileVaultOn = fileVaultOn
        self.notes = notes
    }
}

/// Local sharing / remote access posture (path heuristics only, no port scan).
public struct NetworkState: Codable, Sendable, Equatable {
    public struct Reachability: Sendable {
        public var remoteLoginSSH: Bool? = nil
        public var screenSharingARD: Bool? = nil
        public var fileSharingSMB: Bool? = nil

        public init(
            remoteLoginSSH: Bool? = nil,
            screenSharingARD: Bool? = nil,
            fileSharingSMB: Bool? = nil
        ) {
            self.remoteLoginSSH = remoteLoginSSH
            self.screenSharingARD = screenSharingARD
            self.fileSharingSMB = fileSharingSMB
        }
    }

    public struct ArtifactPresence: Sendable {
        public var remoteLoginPlistPresent: Bool? = nil
        public var screenSharingPlistPresent: Bool? = nil
        public var fileSharingPlistPresent: Bool? = nil
        public var remoteManagementPrefsPresent: Bool? = nil
        public var sshdConfigPresent: Bool? = nil

        public init(
            remoteLoginPlistPresent: Bool? = nil,
            screenSharingPlistPresent: Bool? = nil,
            fileSharingPlistPresent: Bool? = nil,
            remoteManagementPrefsPresent: Bool? = nil,
            sshdConfigPresent: Bool? = nil
        ) {
            self.remoteLoginPlistPresent = remoteLoginPlistPresent
            self.screenSharingPlistPresent = screenSharingPlistPresent
            self.fileSharingPlistPresent = fileSharingPlistPresent
            self.remoteManagementPrefsPresent = remoteManagementPrefsPresent
            self.sshdConfigPresent = sshdConfigPresent
        }
    }

    /// Conservative "likely enabled" signals (nil = unknown).
    public var remoteLoginSSH: Bool?
    public var screenSharingARD: Bool?
    public var fileSharingSMB: Bool?
    /// Path inventory (presence ≠ enabled).
    public var remoteLoginPlistPresent: Bool?
    public var screenSharingPlistPresent: Bool?
    public var fileSharingPlistPresent: Bool?
    public var remoteManagementPrefsPresent: Bool?
    public var sshdConfigPresent: Bool?
    public var notes: [String]

    public init(
        reachability: Reachability = .init(),
        artifacts: ArtifactPresence = .init(),
        notes: [String] = []
    ) {
        self.remoteLoginSSH = reachability.remoteLoginSSH
        self.screenSharingARD = reachability.screenSharingARD
        self.fileSharingSMB = reachability.fileSharingSMB
        self.remoteLoginPlistPresent = artifacts.remoteLoginPlistPresent
        self.screenSharingPlistPresent = artifacts.screenSharingPlistPresent
        self.fileSharingPlistPresent = artifacts.fileSharingPlistPresent
        self.remoteManagementPrefsPresent = artifacts.remoteManagementPrefsPresent
        self.sshdConfigPresent = artifacts.sshdConfigPresent
        self.notes = notes
    }
}
