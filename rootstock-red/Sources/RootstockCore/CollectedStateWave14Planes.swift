import Foundation
// MARK: - Wave-14 2026 coverage multi-plane surfaces


/// Automator workflow delivery residual (never executes Automator workflows or plants malicious .workflow bundles).
public struct AutomatorWorkflowState: Codable, Sendable, Equatable {
    public var automatorAppPaths: [String]
    public var workflowSamplePaths: [String]
    public var actionLibraryPaths: [String]
    public var workflowSurfacePresent: Bool?
    public var notes: [String]
    public init(
        automatorAppPaths: [String] = [],
        workflowSamplePaths: [String] = [],
        actionLibraryPaths: [String] = [],
        workflowSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.automatorAppPaths = automatorAppPaths
        self.workflowSamplePaths = workflowSamplePaths
        self.actionLibraryPaths = actionLibraryPaths
        self.workflowSurfacePresent = workflowSurfacePresent
        self.notes = notes
    }
}


/// iCloud Drive / Mobile Documents path plane (never enumerates iCloud file contents or exfiltrates Mobile Documents).
public struct IcloudDrivePathState: Codable, Sendable, Equatable {
    public var mobileDocumentsPaths: [String]
    public var icloudDrivePaths: [String]
    public var cloudKitPaths: [String]
    public var icloudPathSurfacePresent: Bool?
    public var notes: [String]
    public init(
        mobileDocumentsPaths: [String] = [],
        icloudDrivePaths: [String] = [],
        cloudKitPaths: [String] = [],
        icloudPathSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.mobileDocumentsPaths = mobileDocumentsPaths
        self.icloudDrivePaths = icloudDrivePaths
        self.cloudKitPaths = cloudKitPaths
        self.icloudPathSurfacePresent = icloudPathSurfacePresent
        self.notes = notes
    }
}


/// Bluetooth / Continuity proximity residual depth (never enables Bluetooth pairing or spoofs Continuity identities).
public struct BluetoothContinuityDepthState: Codable, Sendable, Equatable {
    public var bluetoothDaemonPaths: [String]
    public var continuitySupportPaths: [String]
    public var btPreferencePaths: [String]
    public var btContinuitySurfacePresent: Bool?
    public var notes: [String]
    public init(
        bluetoothDaemonPaths: [String] = [],
        continuitySupportPaths: [String] = [],
        btPreferencePaths: [String] = [],
        btContinuitySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.bluetoothDaemonPaths = bluetoothDaemonPaths
        self.continuitySupportPaths = continuitySupportPaths
        self.btPreferencePaths = btPreferencePaths
        self.btContinuitySurfacePresent = btContinuitySurfacePresent
        self.notes = notes
    }
}


/// Font validation / ATS dual-use surface (never installs malicious fonts or disables font validation).
public struct FontValidationDualuseState: Codable, Sendable, Equatable {
    public var fontToolPaths: [String]
    public var atsSupportPaths: [String]
    public var userFontPaths: [String]
    public var fontSurfacePresent: Bool?
    public var notes: [String]
    public init(
        fontToolPaths: [String] = [],
        atsSupportPaths: [String] = [],
        userFontPaths: [String] = [],
        fontSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.fontToolPaths = fontToolPaths
        self.atsSupportPaths = atsSupportPaths
        self.userFontPaths = userFontPaths
        self.fontSurfacePresent = fontSurfacePresent
        self.notes = notes
    }
}


/// QuickLook thumbnail cache residual depth (never dumps QuickLook thumbnail bitmap contents as secret material).
public struct QuicklookCacheDepthState: Codable, Sendable, Equatable {
    public var quicklookDaemonPaths: [String]
    public var thumbnailCachePaths: [String]
    public var qlmanagePaths: [String]
    public var quicklookSurfacePresent: Bool?
    public var notes: [String]
    public init(
        quicklookDaemonPaths: [String] = [],
        thumbnailCachePaths: [String] = [],
        qlmanagePaths: [String] = [],
        quicklookSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.quicklookDaemonPaths = quicklookDaemonPaths
        self.thumbnailCachePaths = thumbnailCachePaths
        self.qlmanagePaths = qlmanagePaths
        self.quicklookSurfacePresent = quicklookSurfacePresent
        self.notes = notes
    }
}


/// DNS resolver / mDNSResponder dual-use surface (never rewrites resolver config or poisons DNS caches).
public struct DnsResolverDualuseState: Codable, Sendable, Equatable {
    public var mdnsResponderPaths: [String]
    public var resolverConfigPaths: [String]
    public var dnsToolPaths: [String]
    public var dnsSurfacePresent: Bool?
    public var notes: [String]
    public init(
        mdnsResponderPaths: [String] = [],
        resolverConfigPaths: [String] = [],
        dnsToolPaths: [String] = [],
        dnsSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.mdnsResponderPaths = mdnsResponderPaths
        self.resolverConfigPaths = resolverConfigPaths
        self.dnsToolPaths = dnsToolPaths
        self.dnsSurfacePresent = dnsSurfacePresent
        self.notes = notes
    }
}


/// LaunchServices QuarantineEvents DB residual depth (never deletes QuarantineEvents rows or clears LS quarantine history).
public struct LsQuarantineDbDepthState: Codable, Sendable, Equatable {
    public var quarantineDbPaths: [String]
    public var lsSupportPaths: [String]
    public var quarantineToolHints: [String]
    public var quarantineDbSurfacePresent: Bool?
    public var notes: [String]
    public init(
        quarantineDbPaths: [String] = [],
        lsSupportPaths: [String] = [],
        quarantineToolHints: [String] = [],
        quarantineDbSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.quarantineDbPaths = quarantineDbPaths
        self.lsSupportPaths = lsSupportPaths
        self.quarantineToolHints = quarantineToolHints
        self.quarantineDbSurfacePresent = quarantineDbSurfacePresent
        self.notes = notes
    }
}


/// PAM authentication module residual surface (never installs PAM modules or modifies /etc/pam.d).
public struct PamAuthModuleState: Codable, Sendable, Equatable {
    public var pamConfigPaths: [String]
    public var pamModulePaths: [String]
    public var authdSupportPaths: [String]
    public var pamSurfacePresent: Bool?
    public var notes: [String]
    public init(
        pamConfigPaths: [String] = [],
        pamModulePaths: [String] = [],
        authdSupportPaths: [String] = [],
        pamSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.pamConfigPaths = pamConfigPaths
        self.pamModulePaths = pamModulePaths
        self.authdSupportPaths = authdSupportPaths
        self.pamSurfacePresent = pamSurfacePresent
        self.notes = notes
    }
}


/// Cron / at job dual-use residual depth (never installs cron or at jobs outside the lab root).
public struct CronAtJobDepthState: Codable, Sendable, Equatable {
    public var cronBinaryPaths: [String]
    public var crontabPaths: [String]
    public var atJobPaths: [String]
    public var cronAtSurfacePresent: Bool?
    public var notes: [String]
    public init(
        cronBinaryPaths: [String] = [],
        crontabPaths: [String] = [],
        atJobPaths: [String] = [],
        cronAtSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.cronBinaryPaths = cronBinaryPaths
        self.crontabPaths = crontabPaths
        self.atJobPaths = atJobPaths
        self.cronAtSurfacePresent = cronAtSurfacePresent
        self.notes = notes
    }
}


/// Notes.app metadata collection path plane (never reads Notes body contents or exports note secrets).
public struct NotesMetadataPlaneState: Codable, Sendable, Equatable {
    public var notesAppPaths: [String]
    public var notesStorePaths: [String]
    public var notesContainerPaths: [String]
    public var notesSurfacePresent: Bool?
    public var notes: [String]
    public init(
        notesAppPaths: [String] = [],
        notesStorePaths: [String] = [],
        notesContainerPaths: [String] = [],
        notesSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.notesAppPaths = notesAppPaths
        self.notesStorePaths = notesStorePaths
        self.notesContainerPaths = notesContainerPaths
        self.notesSurfacePresent = notesSurfacePresent
        self.notes = notes
    }
}
