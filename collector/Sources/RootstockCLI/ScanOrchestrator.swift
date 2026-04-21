import Foundation
import Models
import TCC
import Entitlements
import CodeSigning
import XPCServices
import Persistence
import Keychain
import MDM
import Groups
import RemoteAccess
import Firewall
import LoginSession
import AuthorizationDB
import AuthorizationPlugins
import SystemExtensions
import Sudoers
import ProcessSnapshot
import FileACLs
import ShellHooks
import PhysicalSecurity
import ActiveDirectory
import KerberosArtifacts
import Sandbox
import Quarantine

/// Coordinates all data source modules and assembles the final ScanResult.
struct ScanOrchestrator {
    let verbose: Bool

    struct ModuleConfig {
        let tcc: Bool
        let entitlements: Bool
        let codeSigning: Bool
        let xpc: Bool
        let persistence: Bool
        let keychain: Bool
        let mdm: Bool
        let groups: Bool
        let remoteAccess: Bool
        let firewall: Bool
        let loginSessions: Bool
        let authorizationDB: Bool
        let authorizationPlugins: Bool
        let systemExtensions: Bool
        let sudoers: Bool
        let processSnapshot: Bool
        let fileACLs: Bool
        let shellHooks: Bool
        let physicalSecurity: Bool
        let activeDirectory: Bool
        let kerberos: Bool
        let sandbox: Bool
        let quarantine: Bool

        /// Parse a comma-separated module string or "all".
        static func from(_ moduleString: String) -> ModuleConfig {
            let parts = Set(moduleString.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
            let all = parts.contains("all")
            return ModuleConfig(
                tcc: all || parts.contains("tcc"),
                entitlements: all || parts.contains("entitlements"),
                codeSigning: all || parts.contains("codesigning"),
                xpc: all || parts.contains("xpc"),
                persistence: all || parts.contains("persistence"),
                keychain: all || parts.contains("keychain"),
                mdm: all || parts.contains("mdm"),
                groups: all || parts.contains("groups"),
                remoteAccess: all || parts.contains("remoteaccess"),
                firewall: all || parts.contains("firewall"),
                loginSessions: all || parts.contains("loginsessions"),
                authorizationDB: all || parts.contains("authorizationdb"),
                authorizationPlugins: all || parts.contains("authplugins"),
                systemExtensions: all || parts.contains("systemextensions"),
                sudoers: all || parts.contains("sudoers"),
                processSnapshot: all || parts.contains("processsnapshot"),
                fileACLs: all || parts.contains("fileacls"),
                shellHooks: all || parts.contains("shellhooks"),
                physicalSecurity: all || parts.contains("physicalsecurity"),
                activeDirectory: all || parts.contains("activedirectory"),
                kerberos: all || parts.contains("kerberos"),
                sandbox: all || parts.contains("sandbox"),
                quarantine: all || parts.contains("quarantine")
            )
        }
    }

    func run(config: ModuleConfig) async -> ScanResult {
        var applications: [Application] = []
        var allErrors: [CollectionError] = []
        let scanStart = Date()

        // Phase 1: Launch independent modules concurrently.
        // TCC, XPC, Persistence, Keychain, and MDM have no data dependencies.
        err("Collecting data sources...")

        async let tccTask = config.tcc
            ? timed { await TCCDataSource().collect() }
            : nil
        async let xpcTask = config.xpc
            ? timed { await XPCDataSource().collect() }
            : nil
        async let persistenceTask = config.persistence
            ? timed { await PersistenceDataSource().collect() }
            : nil
        async let keychainTask = config.keychain
            ? timed { await KeychainDataSource().collect() }
            : nil
        async let mdmTask = config.mdm
            ? timed { await MDMDataSource().collect() }
            : nil
        async let groupsTask = config.groups
            ? timed { await GroupDataSource().collect() }
            : nil
        async let remoteAccessTask = config.remoteAccess
            ? timed { await RemoteAccessDataSource().collect() }
            : nil
        async let firewallTask = config.firewall
            ? timed { await FirewallDataSource().collect() }
            : nil
        async let loginSessionsTask = config.loginSessions
            ? timed { await LoginSessionDataSource().collect() }
            : nil
        async let authorizationDBTask = config.authorizationDB
            ? timed { await AuthorizationDBDataSource().collect() }
            : nil
        async let authPluginsTask = config.authorizationPlugins
            ? timed { await AuthorizationPluginDataSource().collect() }
            : nil
        async let sysExtTask = config.systemExtensions
            ? timed { await SystemExtensionDataSource().collect() }
            : nil
        async let sudoersTask = config.sudoers
            ? timed { await SudoersDataSource().collect() }
            : nil
        async let fileACLsTask = config.fileACLs
            ? timed { await FileACLDataSource().collect() }
            : nil
        async let shellHooksTask = config.shellHooks
            ? timed { await ShellHookDataSource().collect() }
            : nil
        async let physicalSecurityTask = config.physicalSecurity
            ? timed { await PhysicalSecurityDataSource().collectAll() }
            : nil
        async let activeDirectoryTask = config.activeDirectory
            ? timed { ActiveDirectoryDataSource().collectWithBinding() }
            : nil
        async let kerberosTask2 = config.kerberos
            ? timed { await KerberosArtifactDataSource().collect() }
            : nil
        // System posture checks run concurrently with other modules
        async let gatekeeperTask: Bool? = { Self.detectGatekeeper() }()
        async let sipTask: Bool? = { Self.detectSIP() }()
        async let filevaultTask: Bool? = { Self.detectFileVault() }()
        async let icloudTask: (Bool?, Bool?, Bool?) = { Self.detectICloudStatus() }()

        // Phase 2: Entitlements → CodeSigning (sequential dependency).
        var entElapsed = 0.0
        var csElapsed = 0.0
        if config.entitlements {
            let (result, elapsed) = await timed { await EntitlementDataSource().collect() }
            applications = result.nodes.compactMap { $0 as? Application }
            allErrors.append(contentsOf: result.errors)
            entElapsed = elapsed
        }
        if config.codeSigning {
            let (csErrors, elapsed) = await timed { CodeSigningDataSource().enrich(applications: &applications) }
            allErrors.append(contentsOf: csErrors)
            csElapsed = elapsed
        }
        if config.entitlements && (config.sandbox || config.quarantine) {
            let enrichStart = Date()
            let appSnapshot = applications  // copy for concurrent reads

            if config.sandbox && config.quarantine {
                // Run both enrichments concurrently using async let
                async let sandboxResult = { SandboxDataSource().enriched(applications: appSnapshot) }()
                async let quarantineResult = { QuarantineDataSource().enriched(applications: appSnapshot) }()
                let ((sandboxApps, sandboxCount), (quarantineApps, quarantineCount)) = await (sandboxResult, quarantineResult)

                // Merge: sandbox writes sandboxProfile, quarantine writes quarantineInfo.
                // Start from sandbox results and overlay quarantine data.
                // ORDERING DEPENDENCY: Both enriched() calls receive the same
                // appSnapshot and return arrays in the same order, so index-based
                // merge is safe. If either enriched() reorders or filters the array,
                // this merge must switch to bundle_id lookup instead.
                applications = sandboxApps
                for i in applications.indices {
                    applications[i] = applications[i].with(quarantineInfo: quarantineApps[i].quarantineInfo)
                }

                let elapsed = Date().timeIntervalSince(enrichStart)
                if verbose {
                    err("  [Sandbox]      completed in \(format(elapsed))  (\(sandboxCount) profiles)")
                    err("  [Quarantine]   completed in \(format(elapsed))  (\(quarantineCount) quarantined)")
                }
            } else if config.sandbox {
                let (sandboxApps, sandboxCount) = SandboxDataSource().enriched(applications: appSnapshot)
                applications = sandboxApps
                let elapsed = Date().timeIntervalSince(enrichStart)
                if verbose { err("  [Sandbox]      completed in \(format(elapsed))  (\(sandboxCount) profiles)") }
            } else {
                let (quarantineApps, quarantineCount) = QuarantineDataSource().enriched(applications: appSnapshot)
                applications = quarantineApps
                let elapsed = Date().timeIntervalSince(enrichStart)
                if verbose { err("  [Quarantine]   completed in \(format(elapsed))  (\(quarantineCount) quarantined)") }
            }
        }

        // Phase 3: Await concurrent results.
        var tccGrants: [TCCGrant] = []
        if let (result, elapsed) = await tccTask {
            tccGrants = result.nodes.compactMap { $0 as? TCCGrant }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [TCC]          completed in \(format(elapsed))  (\(tccGrants.count) grants, \(result.errors.count) errors)") }
        }
        if verbose && config.entitlements {
            err("  [Entitlements] completed in \(format(entElapsed))  (\(applications.count) apps)")
        }
        if verbose && config.codeSigning {
            err("  [CodeSigning]  completed in \(format(csElapsed))  (\(applications.count) apps)")
        }

        var xpcServices: [XPCService] = []
        if let (result, elapsed) = await xpcTask {
            xpcServices = result.nodes.compactMap { $0 as? XPCService }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [XPC]          completed in \(format(elapsed))  (\(xpcServices.count) services, \(result.errors.count) errors)") }
        }

        var launchItems: [LaunchItem] = []
        if let (result, elapsed) = await persistenceTask {
            launchItems = result.nodes.compactMap { $0 as? LaunchItem }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Persistence]  completed in \(format(elapsed))  (\(launchItems.count) items, \(result.errors.count) errors)") }
        }

        var keychainAcls: [KeychainItem] = []
        if let (result, elapsed) = await keychainTask {
            keychainAcls = result.nodes.compactMap { $0 as? KeychainItem }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Keychain]     completed in \(format(elapsed))  (\(keychainAcls.count) items, \(result.errors.count) errors)") }
        }

        var mdmProfiles: [MDMProfile] = []
        if let (result, elapsed) = await mdmTask {
            mdmProfiles = result.nodes.compactMap { $0 as? MDMProfile }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [MDM]          completed in \(format(elapsed))  (\(mdmProfiles.count) profiles, \(result.errors.count) errors)") }
        }

        var localGroups: [LocalGroup] = []
        var userDetails: [UserDetail] = []
        if let (result, elapsed) = await groupsTask {
            localGroups = result.nodes.compactMap { $0 as? LocalGroup }
            userDetails = result.nodes.compactMap { $0 as? UserDetail }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Groups]       completed in \(format(elapsed))  (\(localGroups.count) groups, \(userDetails.count) users, \(result.errors.count) errors)") }
        }

        var remoteAccessServices: [RemoteAccessService] = []
        if let (result, elapsed) = await remoteAccessTask {
            remoteAccessServices = result.nodes.compactMap { $0 as? RemoteAccessService }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [RemoteAccess] completed in \(format(elapsed))  (\(remoteAccessServices.count) services, \(result.errors.count) errors)") }
        }

        var firewallStatus: [FirewallStatus] = []
        if let (result, elapsed) = await firewallTask {
            firewallStatus = result.nodes.compactMap { $0 as? FirewallStatus }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Firewall]     completed in \(format(elapsed))  (\(firewallStatus.count) policies, \(result.errors.count) errors)") }
        }

        var loginSessions: [LoginSession] = []
        if let (result, elapsed) = await loginSessionsTask {
            loginSessions = result.nodes.compactMap { $0 as? LoginSession }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Sessions]     completed in \(format(elapsed))  (\(loginSessions.count) sessions, \(result.errors.count) errors)") }
        }

        var authorizationRights: [AuthorizationRight] = []
        if let (result, elapsed) = await authorizationDBTask {
            authorizationRights = result.nodes.compactMap { $0 as? AuthorizationRight }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [AuthDB]       completed in \(format(elapsed))  (\(authorizationRights.count) rights, \(result.errors.count) errors)") }
        }

        var authorizationPlugins: [AuthorizationPlugin] = []
        if let (result, elapsed) = await authPluginsTask {
            authorizationPlugins = result.nodes.compactMap { $0 as? AuthorizationPlugin }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [AuthPlugins]  completed in \(format(elapsed))  (\(authorizationPlugins.count) plugins, \(result.errors.count) errors)") }
        }

        var systemExtensions: [SystemExtension] = []
        if let (result, elapsed) = await sysExtTask {
            systemExtensions = result.nodes.compactMap { $0 as? SystemExtension }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [SysExt]       completed in \(format(elapsed))  (\(systemExtensions.count) extensions, \(result.errors.count) errors)") }
        }

        var sudoersRules: [SudoersRule] = []
        if let (result, elapsed) = await sudoersTask {
            sudoersRules = result.nodes.compactMap { $0 as? SudoersRule }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Sudoers]      completed in \(format(elapsed))  (\(sudoersRules.count) rules, \(result.errors.count) errors)") }
        }

        var fileAcls: [FileACL] = []
        if let (result, elapsed) = await fileACLsTask {
            fileAcls = result.nodes.compactMap { $0 as? FileACL }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [FileACLs]     completed in \(format(elapsed))  (\(fileAcls.count) items, \(result.errors.count) errors)") }
        }

        if let (result, elapsed) = await shellHooksTask {
            let hooks = result.nodes.compactMap { $0 as? FileACL }
            fileAcls.append(contentsOf: hooks)
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [ShellHooks]   completed in \(format(elapsed))  (\(hooks.count) hooks, \(result.errors.count) errors)") }
        }

        var bluetoothDevices: [BluetoothDevice] = []
        var lockdownModeEnabled: Bool? = nil
        var bluetoothEnabled: Bool? = nil
        var bluetoothDiscoverable: Bool? = nil
        var screenLockEnabled: Bool? = nil
        var screenLockDelay: Int? = nil
        var displaySleepTimeout: Int? = nil
        var thunderboltSecurityLevel: String? = nil
        var secureBootLevel: String? = nil
        var externalBootAllowed: Bool? = nil
        if let (result, elapsed) = await physicalSecurityTask {
            bluetoothDevices = result.bluetoothDevices
            lockdownModeEnabled = result.lockdownModeEnabled
            bluetoothEnabled = result.bluetoothEnabled
            bluetoothDiscoverable = result.bluetoothDiscoverable
            screenLockEnabled = result.screenLockEnabled
            screenLockDelay = result.screenLockDelay
            displaySleepTimeout = result.displaySleepTimeout
            thunderboltSecurityLevel = result.thunderboltSecurityLevel
            secureBootLevel = result.secureBootLevel
            externalBootAllowed = result.externalBootAllowed
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Physical]     completed in \(format(elapsed))  (\(bluetoothDevices.count) BT devices, \(result.errors.count) errors)") }
        }

        var adBinding: ADBinding? = nil
        var adUserDetails: [UserDetail] = []
        var adLocalGroups: [LocalGroup] = []
        if let (combined, elapsed) = await activeDirectoryTask {
            adBinding = combined.binding
            adUserDetails = combined.result.nodes.compactMap { $0 as? UserDetail }
            adLocalGroups = combined.result.nodes.compactMap { $0 as? LocalGroup }
            allErrors.append(contentsOf: combined.result.errors)
            if verbose { err("  [AD]           completed in \(format(elapsed))  (bound: \(adBinding?.isBound ?? false), \(adUserDetails.count) AD users, \(adLocalGroups.count) AD-sourced groups, \(combined.result.errors.count) errors)") }
        }

        var kerberosArtifacts: [KerberosArtifact] = []
        if let (result, elapsed) = await kerberosTask2 {
            kerberosArtifacts = result.nodes.compactMap { $0 as? KerberosArtifact }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Kerberos]     completed in \(format(elapsed))  (\(kerberosArtifacts.count) artifacts, \(result.errors.count) errors)") }
        }

        // Process snapshot runs after entitlements so it can resolve bundle IDs
        var runningProcesses: [RunningProcess] = []
        if config.processSnapshot {
            let (result, elapsed) = await timed { await ProcessSnapshotDataSource(knownApps: applications).collect() }
            runningProcesses = result.nodes.compactMap { $0 as? RunningProcess }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Processes]    completed in \(format(elapsed))  (\(runningProcesses.count) processes, \(result.errors.count) errors)") }
        }

        let gatekeeperEnabled = await gatekeeperTask
        let sipEnabled = await sipTask
        let filevaultEnabled = await filevaultTask
        let (icloudSignedIn, icloudDriveEnabled, icloudKeychainEnabled) = await icloudTask

        if verbose {
            let totalElapsed = Date().timeIntervalSince(scanStart)
            err("  Total: \(format(totalElapsed))")
        }

        return ScanResult(
            scanId: UUID().uuidString,
            timestamp: ISO8601DateFormatter().string(from: Date()),
            hostname: ProcessInfo.processInfo.hostName,
            macosVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            collectorVersion: RootstockCommand.collectorVersion,
            elevation: ElevationInfo(isRoot: getuid() == 0, hasFda: detectFDA()),
            applications: applications,
            tccGrants: tccGrants,
            xpcServices: xpcServices,
            keychainAcls: keychainAcls,
            mdmProfiles: mdmProfiles,
            launchItems: launchItems,
            localGroups: localGroups + adLocalGroups,
            remoteAccessServices: remoteAccessServices,
            firewallStatus: firewallStatus,
            loginSessions: loginSessions,
            authorizationRights: authorizationRights,
            authorizationPlugins: authorizationPlugins,
            systemExtensions: systemExtensions,
            sudoersRules: sudoersRules,
            runningProcesses: runningProcesses,
            userDetails: userDetails + adUserDetails,
            fileAcls: fileAcls,
            bluetoothDevices: bluetoothDevices,
            adBinding: adBinding,
            kerberosArtifacts: kerberosArtifacts,
            sandboxProfiles: applications.compactMap(\.sandboxProfile),
            gatekeeperEnabled: gatekeeperEnabled,
            sipEnabled: sipEnabled,
            filevaultEnabled: filevaultEnabled,
            lockdownModeEnabled: lockdownModeEnabled,
            bluetoothEnabled: bluetoothEnabled,
            bluetoothDiscoverable: bluetoothDiscoverable,
            screenLockEnabled: screenLockEnabled,
            screenLockDelay: screenLockDelay,
            displaySleepTimeout: displaySleepTimeout,
            thunderboltSecurityLevel: thunderboltSecurityLevel,
            secureBootLevel: secureBootLevel,
            externalBootAllowed: externalBootAllowed,
            icloudSignedIn: icloudSignedIn,
            icloudDriveEnabled: icloudDriveEnabled,
            icloudKeychainEnabled: icloudKeychainEnabled,
            errors: allErrors
        )
    }

    // MARK: - Private

    /// Returns nil if spctl is unavailable.
    private static func detectGatekeeper() -> Bool? {
        guard let output = Shell.run("/usr/sbin/spctl", ["--status"]) else { return nil }
        return output.contains("enabled")
    }

    /// Returns nil if csrutil is unavailable.
    private static func detectSIP() -> Bool? {
        guard let output = Shell.run("/usr/bin/csrutil", ["status"]) else { return nil }
        return output.contains("enabled")
    }

    /// Returns nil if fdesetup is unavailable.
    private static func detectFileVault() -> Bool? {
        guard let output = Shell.run("/usr/bin/fdesetup", ["status"]) else { return nil }
        return output.contains("FileVault is On")
    }

    /// Detect iCloud sign-in, Drive, and Keychain sync status from MobileMeAccounts.plist.
    private static func detectICloudStatus() -> (Bool?, Bool?, Bool?) {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let plistPath = "\(home)/Library/Preferences/MobileMeAccounts.plist"
        guard let data = FileManager.default.contents(atPath: plistPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let accounts = plist["Accounts"] as? [[String: Any]] else {
            return (nil, nil, nil)
        }
        let signedIn = !accounts.isEmpty
        var driveEnabled = false
        var keychainEnabled = false
        for account in accounts {
            if let services = account["Services"] as? [String: Any] {
                if services["MOBILE_DOCUMENTS"] != nil { driveEnabled = true }
                if services["KEYCHAIN_SYNC"] != nil { keychainEnabled = true }
            }
        }
        return (signedIn, driveEnabled, keychainEnabled)
    }

    /// Detects Full Disk Access by attempting to read the system TCC database.
    private func detectFDA() -> Bool {
        let systemTCC = "/Library/Application Support/com.apple.TCC/TCC.db"
        return FileManager.default.isReadableFile(atPath: systemTCC)
    }

    /// Runs `block`, returning the result and wall-clock elapsed time in seconds.
    private func timed<T>(_ block: () async -> T) async -> (T, Double) {
        let start = Date()
        let result = await block()
        return (result, Date().timeIntervalSince(start))
    }

    /// Formats elapsed seconds as "X.XXs".
    private func format(_ seconds: Double) -> String {
        String(format: "%.2fs", seconds)
    }

    /// Write a line to stderr.
    private func err(_ text: String) {
        FileHandle.standardError.write(Data((text + "\n").utf8))
    }
}
