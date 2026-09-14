import Foundation

/// Documented macOS event field names for offline and synthetic exports.
/// Keep in sync with `Content/field-taxonomy/macos-events.yaml`.
public enum FieldTaxonomy {
    public static let processPath = "process.executable.path"
    public static let processPid = "process.pid"
    public static let processPpid = "process.ppid"
    public static let processSigningID = "process.code_signature.signing_id"
    public static let processTeamID = "process.code_signature.team_id"
    public static let processCDHash = "process.code_signature.cdhash"
    public static let processSigned = "process.code_signature.signed"
    public static let filePath = "file.path"
    public static let fileDestinationPath = "file.destination.path"
    public static let eventType = "event.type"
    public static let userName = "user.name"
    public static let tccService = "tcc.service"
    public static let tccIdentity = "tcc.identity"
    public static let tccRight = "tcc.right"
    public static let btmItemType = "btm.item_type"
    public static let btmItemPath = "btm.item_path"
    public static let xprotectMalware = "xprotect.malware_identifier"

    // Pattern-of-life / Biome
    public static let polStream = "pol.stream"
    public static let polValue = "pol.value"
    public static let polSource = "pol.source"

    // Persistence (cron, login items, launchd)
    public static let persistenceKind = "persistence.kind"
    public static let persistenceSchedule = "persistence.schedule"
    public static let persistenceCommand = "persistence.command"
    public static let persistenceLabel = "persistence.label"
    public static let persistencePath = "persistence.path"
    public static let persistenceProgram = "persistence.program"

    // System / browser extensions
    public static let extensionBundleID = "extension.bundle_id"
    public static let extensionState = "extension.state"
    public static let extensionTeamID = "extension.team_id"
    public static let extensionID = "extension.id"
    public static let extensionName = "extension.name"
    public static let extensionVersion = "extension.version"
    public static let extensionPermissions = "extension.permissions"

    // Auth / utmpx
    public static let authTTY = "auth.tty"
    public static let authHost = "auth.host"
    public static let authType = "auth.type"

    // Gatekeeper
    public static let gatekeeperResult = "gatekeeper.result"
    public static let gatekeeperPolicy = "gatekeeper.policy"

    // Network location
    public static let netService = "net.service"
    public static let netInterface = "net.interface"
    public static let netIPv4 = "net.ipv4"

    // Browser
    public static let browserName = "browser.name"

    // Hardening assessment
    public static let hardenControl = "harden.control"
    public static let hardenStatus = "harden.status"
    public static let hardenSeverity = "harden.severity"
    public static let hardenRemediation = "harden.remediation"

    // Privilege / sudoers
    public static let privilegeKind = "privilege.kind"
    public static let privilegeLine = "privilege.line"
    public static let privilegeRiskTags = "privilege.risk_tags"

    // Defense / launchd overrides
    public static let defenseKind = "defense.kind"
    public static let defenseLabel = "defense.label"
    public static let defenseDisabled = "defense.disabled"

    // Shell profile risk
    public static let shellRisk = "shell.risk"
    public static let shellProfileScope = "shell.profile_scope"

    // privileged helpers / folder actions / login hooks
    public static let privhelperLabel = "privhelper.label"
    public static let privhelperBundleID = "privhelper.bundle_id"
    public static let folderActionName = "folder_action.name"
    public static let folderActionWatched = "folder_action.watched_path"
    public static let loginHookType = "loginwindow.hook_type"

    // access / account posture
    public static let remoteService = "remote.service"
    public static let remoteEnabled = "remote.enabled"
    public static let accountGuestEnabled = "account.guest_enabled"
    public static let accountAutoLogin = "account.auto_login_user"

    public static let allKnown: [String] = [
        processPath, processPid, processPpid,
        processSigningID, processTeamID, processCDHash, processSigned,
        filePath, fileDestinationPath, eventType, userName,
        tccService, tccIdentity, tccRight,
        btmItemType, btmItemPath, xprotectMalware,
        polStream, polValue, polSource,
        persistenceKind, persistenceSchedule, persistenceCommand, persistenceLabel, persistencePath, persistenceProgram,
        extensionBundleID, extensionState, extensionTeamID,
        extensionID, extensionName, extensionVersion, extensionPermissions,
        authTTY, authHost, authType,
        gatekeeperResult, gatekeeperPolicy,
        netService, netInterface, netIPv4,
        browserName,
        hardenControl, hardenStatus, hardenSeverity, hardenRemediation,
        privilegeKind, privilegeLine, privilegeRiskTags,
        defenseKind, defenseLabel, defenseDisabled,
        shellRisk, shellProfileScope,
        privhelperLabel, privhelperBundleID,
        folderActionName, folderActionWatched, loginHookType,
        remoteService, remoteEnabled,
        accountGuestEnabled, accountAutoLogin,
    ]
}

/// Event type values shared by Blue producers and the family exporter.
///
/// These are event semantics, not source-plugin labels. Importers must retain
/// their provenance in `EventEnvelope.identity` and `sourcePlugin` instead of
/// inventing source-specific event types.
public enum EventVocabulary {
    public static let collectorScanMeta = "collector.scan_meta"
    public static let tccGrant = "tcc.grant"
    public static let persistenceItem = "persistence.item"
    public static let persistenceLaunchItem = "persistence.launch_item"
    public static let postureHost = "ir.posture.host"
    public static let postureProtection = "ir.posture.protection"
    public static let importedFinding = "finding.import"

    public static func isPersistence(_ eventType: String) -> Bool {
        eventType == persistenceItem || eventType == persistenceLaunchItem
    }
}
