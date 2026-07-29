import Foundation

// MARK: - Wave-11 2026 coverage multi-plane surfaces

/// Custom URL scheme / document-handler delivery posture (never registers schemes or handlers).
public struct URLSchemeHandlerState: Codable, Sendable, Equatable {
    /// LaunchServices / LS handlers database path hits.
    public var launchServicesPaths: [String]
    /// Sample app Info.plist / CFBundleURLTypes adjacent path hits.
    public var urlTypePlistPaths: [String]
    /// Document type / UTI handler adjacency path hits.
    public var documentHandlerPaths: [String]
    /// Dual-use openers (open, osascript, openurl helpers) path hits.
    public var openerBinaryPaths: [String]
    /// Whether a URL scheme / document handler surface was observed.
    public var handlerSurfacePresent: Bool?
    public var notes: [String]

    public init(
        launchServicesPaths: [String] = [],
        urlTypePlistPaths: [String] = [],
        documentHandlerPaths: [String] = [],
        openerBinaryPaths: [String] = [],
        handlerSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.launchServicesPaths = launchServicesPaths
        self.urlTypePlistPaths = urlTypePlistPaths
        self.documentHandlerPaths = documentHandlerPaths
        self.openerBinaryPaths = openerBinaryPaths
        self.handlerSurfacePresent = handlerSurfacePresent
        self.notes = notes
    }
}

/// Launchd disabled / override depth posture (never disables security jobs).
public struct LaunchdOverrideDepthState: Codable, Sendable, Equatable {
    /// disabled.plist / overrides.plist path hits.
    public var overridePlistPaths: [String]
    /// Security-product label hints observed as disabled (path/meta only).
    public var securityDisabledHints: [String]
    /// KeepAlive / ThrottleInterval adjacency notes as path hits.
    public var keepaliveAdjacentPaths: [String]
    /// Whether an override-depth surface was observed.
    public var overrideSurfacePresent: Bool?
    public var notes: [String]

    public init(
        overridePlistPaths: [String] = [],
        securityDisabledHints: [String] = [],
        keepaliveAdjacentPaths: [String] = [],
        overrideSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.overridePlistPaths = overridePlistPaths
        self.securityDisabledHints = securityDisabledHints
        self.keepaliveAdjacentPaths = keepaliveAdjacentPaths
        self.overrideSurfacePresent = overrideSurfacePresent
        self.notes = notes
    }
}

/// Browser extension dual-use persistence / collection plane (never dumps extension secrets).
public struct BrowserExtensionDualUseState: Codable, Sendable, Equatable {
    /// Chromium-class extension root path hits.
    public var chromiumExtensionPaths: [String]
    /// Safari App Extension / WebExtension path hits.
    public var safariExtensionPaths: [String]
    /// Preferences / Secure Preferences adjacency path hits.
    public var preferencePaths: [String]
    /// Whether a dual-use extension surface was observed.
    public var extensionSurfacePresent: Bool?
    public var notes: [String]

    public init(
        chromiumExtensionPaths: [String] = [],
        safariExtensionPaths: [String] = [],
        preferencePaths: [String] = [],
        extensionSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.chromiumExtensionPaths = chromiumExtensionPaths
        self.safariExtensionPaths = safariExtensionPaths
        self.preferencePaths = preferencePaths
        self.extensionSurfacePresent = extensionSurfacePresent
        self.notes = notes
    }
}

/// Shortcuts / App Intents automation lateral posture (never runs shortcuts or forges intents).
public struct ShortcutsAppIntentsState: Codable, Sendable, Equatable {
    /// Shortcuts.app / Workflows database path hits.
    public var shortcutsAppPaths: [String]
    /// App Intents / AppShortcuts support path hits.
    public var appIntentsPaths: [String]
    /// Automation / personal automation preference path hits.
    public var automationPrefPaths: [String]
    /// Whether a Shortcuts/App Intents surface was observed.
    public var automationSurfacePresent: Bool?
    public var notes: [String]

    public init(
        shortcutsAppPaths: [String] = [],
        appIntentsPaths: [String] = [],
        automationPrefPaths: [String] = [],
        automationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.shortcutsAppPaths = shortcutsAppPaths
        self.appIntentsPaths = appIntentsPaths
        self.automationPrefPaths = automationPrefPaths
        self.automationSurfacePresent = automationSurfacePresent
        self.notes = notes
    }
}


// MARK: - Wave-12 2026 coverage multi-plane surfaces

/// Webloc / Internet Location file delivery (never crafts phishing webloc/inetloc payloads or rewrites Internet Location files).
public struct WeblocInetlocDeliveryState: Codable, Sendable, Equatable {
    public var weblocSamplePaths: [String]
    public var inetlocSamplePaths: [String]
    public var dropFolderHints: [String]
    public var deliverySurfacePresent: Bool?
    public var notes: [String]

    public init(
        weblocSamplePaths: [String] = [],
        inetlocSamplePaths: [String] = [],
        dropFolderHints: [String] = [],
        deliverySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.weblocSamplePaths = weblocSamplePaths
        self.inetlocSamplePaths = inetlocSamplePaths
        self.dropFolderHints = dropFolderHints
        self.deliverySurfacePresent = deliverySurfacePresent
        self.notes = notes
    }
}


/// Mail rules / Apple Mail automation persistence (never reads Mail contents or modifies user Mail rules).
public struct MailRulesAutomationState: Codable, Sendable, Equatable {
    public var mailAppPaths: [String]
    public var rulesPlistPaths: [String]
    public var scriptingAdjacentPaths: [String]
    public var rulesSurfacePresent: Bool?
    public var notes: [String]

    public init(
        mailAppPaths: [String] = [],
        rulesPlistPaths: [String] = [],
        scriptingAdjacentPaths: [String] = [],
        rulesSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.mailAppPaths = mailAppPaths
        self.rulesPlistPaths = rulesPlistPaths
        self.scriptingAdjacentPaths = scriptingAdjacentPaths
        self.rulesSurfacePresent = rulesSurfacePresent
        self.notes = notes
    }
}


/// Unified log / logarchive observation depth (never dumps private unified-log message bodies or force-collects other users' logarchives).
public struct UnifiedLogObservationState: Codable, Sendable, Equatable {
    public var logToolPaths: [String]
    public var logarchiveHints: [String]
    public var privacyPrefPaths: [String]
    public var observationSurfacePresent: Bool?
    public var notes: [String]

    public init(
        logToolPaths: [String] = [],
        logarchiveHints: [String] = [],
        privacyPrefPaths: [String] = [],
        observationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.logToolPaths = logToolPaths
        self.logarchiveHints = logarchiveHints
        self.privacyPrefPaths = privacyPrefPaths
        self.observationSurfacePresent = observationSurfacePresent
        self.notes = notes
    }
}


/// Dock persistent apps / recent items dual-use (never modifies Dock.plist or plants malicious Dock entries).
public struct DockPersistenceSurfaceState: Codable, Sendable, Equatable {
    public var dockPlistPaths: [String]
    public var recentItemsPaths: [String]
    public var dockDbHints: [String]
    public var dockSurfacePresent: Bool?
    public var notes: [String]

    public init(
        dockPlistPaths: [String] = [],
        recentItemsPaths: [String] = [],
        dockDbHints: [String] = [],
        dockSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.dockPlistPaths = dockPlistPaths
        self.recentItemsPaths = recentItemsPaths
        self.dockDbHints = dockDbHints
        self.dockSurfacePresent = dockSurfacePresent
        self.notes = notes
    }
}


/// Compiled AppleScript / OSA delivery residual (never compiles malicious .scpt payloads or executes third-party AppleScripts).
public struct OsascriptScptDeliveryState: Codable, Sendable, Equatable {
    public var osaToolPaths: [String]
    public var scriptEditorPaths: [String]
    public var scptDropHints: [String]
    public var scptSurfacePresent: Bool?
    public var notes: [String]

    public init(
        osaToolPaths: [String] = [],
        scriptEditorPaths: [String] = [],
        scptDropHints: [String] = [],
        scptSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.osaToolPaths = osaToolPaths
        self.scriptEditorPaths = scriptEditorPaths
        self.scptDropHints = scptDropHints
        self.scptSurfacePresent = scptSurfacePresent
        self.notes = notes
    }
}


/// Network share / SMB mount dual-use lateral (never mounts attacker shares or writes credentials to NetAuth).
public struct NetworkShareMountState: Codable, Sendable, Equatable {
    public var smbClientPaths: [String]
    public var netAuthPaths: [String]
    public var mountPointHints: [String]
    public var shareSurfacePresent: Bool?
    public var notes: [String]

    public init(
        smbClientPaths: [String] = [],
        netAuthPaths: [String] = [],
        mountPointHints: [String] = [],
        shareSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.smbClientPaths = smbClientPaths
        self.netAuthPaths = netAuthPaths
        self.mountPointHints = mountPointHints
        self.shareSurfacePresent = shareSurfacePresent
        self.notes = notes
    }
}


// MARK: - Wave-13 2026 coverage multi-plane surfaces


/// Calendar / Reminders automation lateral surface (never reads event contents or creates malicious calendar invites).
public struct CalendarRemindersAutomationState: Codable, Sendable, Equatable {
    public var calendarAppPaths: [String]
    public var remindersPaths: [String]
    public var eventKitPaths: [String]
    public var automationSurfacePresent: Bool?
    public var notes: [String]

    public init(
        calendarAppPaths: [String] = [],
        remindersPaths: [String] = [],
        eventKitPaths: [String] = [],
        automationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.calendarAppPaths = calendarAppPaths
        self.remindersPaths = remindersPaths
        self.eventKitPaths = eventKitPaths
        self.automationSurfacePresent = automationSurfacePresent
        self.notes = notes
    }
}


/// Gatekeeper assessment / syspolicyd history depth (never clears Gatekeeper assessments or disables syspolicyd).
public struct GatekeeperAssessmentHistoryState: Codable, Sendable, Equatable {
    public var syspolicydPaths: [String]
    public var assessmentDbPaths: [String]
    public var spctlToolPaths: [String]
    public var assessmentSurfacePresent: Bool?
    public var notes: [String]

    public init(
        syspolicydPaths: [String] = [],
        assessmentDbPaths: [String] = [],
        spctlToolPaths: [String] = [],
        assessmentSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.syspolicydPaths = syspolicydPaths
        self.assessmentDbPaths = assessmentDbPaths
        self.spctlToolPaths = spctlToolPaths
        self.assessmentSurfacePresent = assessmentSurfacePresent
        self.notes = notes
    }
}


/// Homebrew / third-party package manager dual-use (never installs packages or modifies Homebrew formulae).
public struct HomebrewPackageDualUseState: Codable, Sendable, Equatable {
    public var brewBinaryPaths: [String]
    public var cellarPaths: [String]
    public var tapPaths: [String]
    public var packageSurfacePresent: Bool?
    public var notes: [String]

    public init(
        brewBinaryPaths: [String] = [],
        cellarPaths: [String] = [],
        tapPaths: [String] = [],
        packageSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.brewBinaryPaths = brewBinaryPaths
        self.cellarPaths = cellarPaths
        self.tapPaths = tapPaths
        self.packageSurfacePresent = packageSurfacePresent
        self.notes = notes
    }
}


/// CUPS / printer dual-use residual surface (never submits print jobs or reconfigures CUPS remotely).
public struct CupsPrintDualUseState: Codable, Sendable, Equatable {
    public var cupsDaemonPaths: [String]
    public var ppdConfigPaths: [String]
    public var printToolPaths: [String]
    public var printSurfacePresent: Bool?
    public var notes: [String]

    public init(
        cupsDaemonPaths: [String] = [],
        ppdConfigPaths: [String] = [],
        printToolPaths: [String] = [],
        printSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.cupsDaemonPaths = cupsDaemonPaths
        self.ppdConfigPaths = ppdConfigPaths
        self.printToolPaths = printToolPaths
        self.printSurfacePresent = printSurfacePresent
        self.notes = notes
    }
}


/// ScreenCapture / screenshot privacy dual-use depth (never captures screens or dumps Screen Recording TCC rows).
public struct ScreenCapturePrivacyDualUseState: Codable, Sendable, Equatable {
    public var screencaptureToolPaths: [String]
    public var screenCaptureKitPaths: [String]
    public var screenshotDropHints: [String]
    public var captureSurfacePresent: Bool?
    public var notes: [String]

    public init(
        screencaptureToolPaths: [String] = [],
        screenCaptureKitPaths: [String] = [],
        screenshotDropHints: [String] = [],
        captureSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.screencaptureToolPaths = screencaptureToolPaths
        self.screenCaptureKitPaths = screenCaptureKitPaths
        self.screenshotDropHints = screenshotDropHints
        self.captureSurfacePresent = captureSurfacePresent
        self.notes = notes
    }
}
