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

    func run(config: ModuleConfig) async -> ScanResult {
        var allErrors: [CollectionError] = []
        let scanStart = Date()

        // Phase 1: Launch independent modules concurrently.
        // TCC, XPC, Persistence, Keychain, and MDM have no data dependencies.
        err("Collecting data sources...")

        async let moduleTaskResultsTask = collectIndependentModules(config: config)
        async let hostPostureProbeResultsTask = Self.collectHostPostureProbeResults()

        let applicationCollection = await collectApplications(config: config)
        allErrors.append(contentsOf: applicationCollection.errors)
        let applications = applicationCollection.applications

        let modules = await collectScanModules(
            config: config,
            applications: applications,
            taskResults: moduleTaskResultsTask,
            errors: &allErrors
        )

        let hostPosture = collectHostPosture(
            probeResults: await hostPostureProbeResultsTask,
            errors: &allErrors
        )

        if verbose {
            let totalElapsed = Date().timeIntervalSince(scanStart)
            err("  Total: \(format(totalElapsed))")
        }

        return makeScanResult(
            applications: applications,
            modules: modules,
            hostPosture: hostPosture,
            errors: allErrors
        )
    }

    // MARK: - Private

    private func collectIndependentModules(config: ModuleConfig) async -> ModuleTaskResults {
        async let tccTask = collectDataSourceIfIncluded(config, .tcc) { await TCCDataSource().collect() }
        async let xpcTask = collectDataSourceIfIncluded(config, .xpc) { await XPCDataSource().collect() }
        async let persistenceTask = collectDataSourceIfIncluded(config, .persistence) { await PersistenceDataSource().collect() }
        async let keychainTask = collectDataSourceIfIncluded(config, .keychain) { await KeychainDataSource().collect() }
        async let mdmTask = collectDataSourceIfIncluded(config, .mdm) { await MDMDataSource().collect() }
        async let groupsTask = collectDataSourceIfIncluded(config, .groups) { await GroupDataSource().collect() }
        async let remoteAccessTask = collectDataSourceIfIncluded(config, .remoteAccess) { await RemoteAccessDataSource().collect() }
        async let firewallTask = collectDataSourceIfIncluded(config, .firewall) { await FirewallDataSource().collect() }
        async let loginSessionsTask = collectDataSourceIfIncluded(config, .loginSessions) { await LoginSessionDataSource().collect() }
        async let authorizationDBTask = collectDataSourceIfIncluded(config, .authorizationDB) { await AuthorizationDBDataSource().collect() }
        async let authPluginsTask = collectDataSourceIfIncluded(config, .authorizationPlugins) { await AuthorizationPluginDataSource().collect() }
        async let sysExtTask = collectDataSourceIfIncluded(config, .systemExtensions) { await SystemExtensionDataSource().collect() }
        async let sudoersTask = collectDataSourceIfIncluded(config, .sudoers) { await SudoersDataSource().collect() }
        async let fileACLsTask = collectDataSourceIfIncluded(config, .fileACLs) { await FileACLDataSource().collect() }
        async let shellHooksTask = collectDataSourceIfIncluded(config, .shellHooks) { await ShellHookDataSource().collect() }
        async let physicalSecurityTask = collectPhysicalSecurityIfIncluded(config)
        async let activeDirectoryTask = collectActiveDirectoryIfIncluded(config)
        async let kerberosTask = collectDataSourceIfIncluded(config, .kerberos) { await KerberosArtifactDataSource().collect() }
        return await ModuleTaskResults(
            tcc: tccTask,
            xpc: xpcTask,
            persistence: persistenceTask,
            keychain: keychainTask,
            mdm: mdmTask,
            groups: groupsTask,
            remoteAccess: remoteAccessTask,
            firewall: firewallTask,
            loginSessions: loginSessionsTask,
            authorizationDB: authorizationDBTask,
            authorizationPlugins: authPluginsTask,
            systemExtensions: sysExtTask,
            sudoers: sudoersTask,
            fileACLs: fileACLsTask,
            shellHooks: shellHooksTask,
            physicalSecurity: physicalSecurityTask,
            activeDirectory: activeDirectoryTask,
            kerberos: kerberosTask
        )
    }

    private func collectDataSourceIfIncluded(
        _ config: ModuleConfig,
        _ module: RootstockModuleID,
        collect: () async -> DataSourceResult
    ) async -> (DataSourceResult, Double)? {
        guard config.includes(module) else { return nil }
        return await timed { await collect() }
    }

    private func collectPhysicalSecurityIfIncluded(
        _ config: ModuleConfig
    ) async -> (PhysicalSecurityResult, Double)? {
        guard config.includes(.physicalSecurity) else { return nil }
        return await timed { await PhysicalSecurityDataSource().collectAll() }
    }

    private func collectActiveDirectoryIfIncluded(
        _ config: ModuleConfig
    ) async -> ((result: DataSourceResult, binding: ADBinding), Double)? {
        guard config.includes(.activeDirectory) else { return nil }
        return await timed { ActiveDirectoryDataSource().collectWithBinding() }
    }

    private func collectApplications(config: ModuleConfig) async -> ApplicationCollection {
        let entitlementCollection = await collectEntitlementApplications(config: config)
        let codeSigningCollection = await collectCodeSigningApplications(
            config: config,
            applications: entitlementCollection.applications
        )
        let applications = await collectApplicationEnrichments(
            config: config,
            applications: codeSigningCollection.applications
        )
        return ApplicationCollection(
            applications: applications,
            errors: entitlementCollection.errors + codeSigningCollection.errors
        )
    }

    private func collectEntitlementApplications(config: ModuleConfig) async -> ApplicationCollection {
        guard config.includes(.entitlements) else {
            return ApplicationCollection(applications: [], errors: [])
        }
        let (result, elapsed) = await timed { await EntitlementDataSource().collect() }
        let applications = result.nodes.compactMap { $0 as? Application }
        if verbose {
            err("  [Entitlements] completed in \(format(elapsed))  (\(applications.count) apps)")
        }
        return ApplicationCollection(applications: applications, errors: result.errors)
    }

    private func collectCodeSigningApplications(
        config: ModuleConfig,
        applications: [Application]
    ) async -> ApplicationCollection {
        guard config.includes(.codeSigning) else {
            return ApplicationCollection(applications: applications, errors: [])
        }
        let ((enrichedApplications, errors), elapsed) = await timed {
            CodeSigningDataSource().enriched(applications: applications)
        }
        if verbose {
            err("  [CodeSigning]  completed in \(format(elapsed))  (\(enrichedApplications.count) apps)")
        }
        return ApplicationCollection(applications: enrichedApplications, errors: errors)
    }

    private func collectApplicationEnrichments(
        config: ModuleConfig,
        applications: [Application]
    ) async -> [Application] {
        guard config.includes(.entitlements),
              config.includes(.sandbox) || config.includes(.quarantine) else {
            return applications
        }
        if config.includes(.sandbox) && config.includes(.quarantine) {
            return await collectSandboxAndQuarantine(applications)
        }
        let enrichStart = Date()
        if config.includes(.sandbox) {
            let (sandboxApps, sandboxCount) = SandboxDataSource().enriched(applications: applications)
            let elapsed = Date().timeIntervalSince(enrichStart)
            if verbose { err("  [Sandbox]      completed in \(format(elapsed))  (\(sandboxCount) profiles)") }
            return sandboxApps
        }
        let (quarantineApps, quarantineCount) = QuarantineDataSource().enriched(applications: applications)
        let elapsed = Date().timeIntervalSince(enrichStart)
        if verbose { err("  [Quarantine]   completed in \(format(elapsed))  (\(quarantineCount) quarantined)") }
        return quarantineApps
    }

    private func collectSandboxAndQuarantine(_ applications: [Application]) async -> [Application] {
        let enrichStart = Date()
        async let sandboxResult = { SandboxDataSource().enriched(applications: applications) }()
        async let quarantineResult = { QuarantineDataSource().enriched(applications: applications) }()
        let ((sandboxApps, sandboxCount), (quarantineApps, quarantineCount)) = await (sandboxResult, quarantineResult)
        if verbose {
            let elapsed = Date().timeIntervalSince(enrichStart)
            err("  [Sandbox]      completed in \(format(elapsed))  (\(sandboxCount) profiles)")
            err("  [Quarantine]   completed in \(format(elapsed))  (\(quarantineCount) quarantined)")
        }
        return Self.mergeApplicationEnrichments(
            sandboxApplications: sandboxApps,
            quarantineApplications: quarantineApps
        )
    }

    private func collectNodes<T>(
        _ timedResult: (DataSourceResult, Double)?,
        as _: T.Type,
        label: String,
        noun: String,
        errors: inout [CollectionError]
    ) -> [T] {
        guard let (result, elapsed) = timedResult else { return [] }
        let nodes = result.nodes.compactMap { $0 as? T }
        errors.append(contentsOf: result.errors)
        if verbose {
            err("  [\(label)] completed in \(format(elapsed))  (\(nodes.count) \(noun), \(result.errors.count) errors)")
        }
        return nodes
    }

    private func collectScanModules(
        config: ModuleConfig,
        applications: [Application],
        taskResults: ModuleTaskResults,
        errors: inout [CollectionError]
    ) async -> ScanModuleCollection {
        ScanModuleCollection(
            tccGrants: collectNodes(taskResults.tcc, as: TCCGrant.self, label: "TCC", noun: "grants", errors: &errors),
            xpcServices: collectNodes(taskResults.xpc, as: XPCService.self, label: "XPC", noun: "services", errors: &errors),
            keychainAcls: collectNodes(taskResults.keychain, as: KeychainItem.self, label: "Keychain", noun: "items", errors: &errors),
            mdmProfiles: collectNodes(taskResults.mdm, as: MDMProfile.self, label: "MDM", noun: "profiles", errors: &errors),
            launchItems: collectNodes(taskResults.persistence, as: LaunchItem.self, label: "Persistence", noun: "items", errors: &errors),
            groupCollection: collectGroups(taskResults.groups, errors: &errors),
            remoteAccessServices: collectNodes(taskResults.remoteAccess, as: RemoteAccessService.self, label: "RemoteAccess", noun: "services", errors: &errors),
            firewallStatus: collectNodes(taskResults.firewall, as: FirewallStatus.self, label: "Firewall", noun: "policies", errors: &errors),
            loginSessions: collectNodes(taskResults.loginSessions, as: LoginSession.self, label: "Sessions", noun: "sessions", errors: &errors),
            authorizationRights: collectNodes(taskResults.authorizationDB, as: AuthorizationRight.self, label: "AuthDB", noun: "rights", errors: &errors),
            authorizationPlugins: collectNodes(taskResults.authorizationPlugins, as: AuthorizationPlugin.self, label: "AuthPlugins", noun: "plugins", errors: &errors),
            systemExtensions: collectNodes(taskResults.systemExtensions, as: SystemExtension.self, label: "SysExt", noun: "extensions", errors: &errors),
            sudoersRules: collectNodes(taskResults.sudoers, as: SudoersRule.self, label: "Sudoers", noun: "rules", errors: &errors),
            runningProcesses: await collectRunningProcesses(config: config, applications: applications, errors: &errors),
            fileAcls: collectFileACLs(taskResults.fileACLs, shellHooks: taskResults.shellHooks, errors: &errors),
            physicalSecurity: collectPhysicalSecurity(taskResults.physicalSecurity, errors: &errors),
            activeDirectory: collectActiveDirectory(taskResults.activeDirectory, errors: &errors),
            kerberosArtifacts: collectNodes(taskResults.kerberos, as: KerberosArtifact.self, label: "Kerberos", noun: "artifacts", errors: &errors)
        )
    }

    private func collectGroups(
        _ timedResult: (DataSourceResult, Double)?,
        errors: inout [CollectionError]
    ) -> GroupCollection {
        guard let (result, elapsed) = timedResult else { return GroupCollection() }
        let groups = result.nodes.compactMap { $0 as? LocalGroup }
        let users = result.nodes.compactMap { $0 as? UserDetail }
        errors.append(contentsOf: result.errors)
        if verbose {
            err("  [Groups]       completed in \(format(elapsed))  (\(groups.count) groups, \(users.count) users, \(result.errors.count) errors)")
        }
        return GroupCollection(localGroups: groups, userDetails: users)
    }

    private func collectFileACLs(
        _ fileACLsResult: (DataSourceResult, Double)?,
        shellHooks: (DataSourceResult, Double)?,
        errors: inout [CollectionError]
    ) -> [FileACL] {
        var fileAcls: [FileACL] = collectNodes(
            fileACLsResult,
            as: FileACL.self,
            label: "FileACLs",
            noun: "items",
            errors: &errors
        )
        guard let (result, elapsed) = shellHooks else { return fileAcls }
        let hooks = result.nodes.compactMap { $0 as? FileACL }
        fileAcls.append(contentsOf: hooks)
        errors.append(contentsOf: result.errors)
        if verbose {
            err("  [ShellHooks]   completed in \(format(elapsed))  (\(hooks.count) hooks, \(result.errors.count) errors)")
        }
        return fileAcls
    }

    private func collectPhysicalSecurity(
        _ timedResult: (PhysicalSecurityResult, Double)?,
        errors: inout [CollectionError]
    ) -> PhysicalSecurityCollection {
        guard let (result, elapsed) = timedResult else { return PhysicalSecurityCollection() }
        errors.append(contentsOf: result.errors)
        if verbose {
            err("  [Physical]     completed in \(format(elapsed))  (\(result.bluetoothDevices.count) BT devices, \(result.errors.count) errors)")
        }
        return PhysicalSecurityCollection(
            bluetoothDevices: result.bluetoothDevices,
            lockdownModeEnabled: result.lockdownModeEnabled,
            bluetoothEnabled: result.bluetoothEnabled,
            bluetoothDiscoverable: result.bluetoothDiscoverable,
            screenLockEnabled: result.screenLockEnabled,
            screenLockDelay: result.screenLockDelay,
            displaySleepTimeout: result.displaySleepTimeout,
            thunderboltSecurityLevel: result.thunderboltSecurityLevel,
            secureBootLevel: result.secureBootLevel,
            externalBootAllowed: result.externalBootAllowed
        )
    }

    private func collectActiveDirectory(
        _ timedResult: ((result: DataSourceResult, binding: ADBinding), Double)?,
        errors: inout [CollectionError]
    ) -> ActiveDirectoryCollection {
        guard let (combined, elapsed) = timedResult else {
            return ActiveDirectoryCollection()
        }
        let users = combined.result.nodes.compactMap { $0 as? UserDetail }
        let groups = combined.result.nodes.compactMap { $0 as? LocalGroup }
        errors.append(contentsOf: combined.result.errors)
        if verbose {
            err("  [AD]           completed in \(format(elapsed))  (bound: \(combined.binding.isBound), \(users.count) AD users, \(groups.count) AD-sourced groups, \(combined.result.errors.count) errors)")
        }
        return ActiveDirectoryCollection(
            binding: combined.binding,
            userDetails: users,
            localGroups: groups
        )
    }

    private func collectRunningProcesses(
        config: ModuleConfig,
        applications: [Application],
        errors: inout [CollectionError]
    ) async -> [RunningProcess] {
        guard config.includes(.processSnapshot) else { return [] }
        let (result, elapsed) = await timed {
            await ProcessSnapshotDataSource(knownApps: applications).collect()
        }
        let runningProcesses = result.nodes.compactMap { $0 as? RunningProcess }
        errors.append(contentsOf: result.errors)
        if verbose {
            err("  [Processes]    completed in \(format(elapsed))  (\(runningProcesses.count) processes, \(result.errors.count) errors)")
        }
        return runningProcesses
    }

    private func collectHostPosture(
        probeResults: HostPostureProbeResults,
        errors: inout [CollectionError]
    ) -> HostPostureCollection {
        errors.append(
            contentsOf: [
                probeResults.gatekeeper.error,
                probeResults.sip.error,
                probeResults.filevault.error,
                probeResults.icloud.error
            ].compactMap { $0 }
        )
        return HostPostureCollection(
            gatekeeperEnabled: probeResults.gatekeeper.value,
            sipEnabled: probeResults.sip.value,
            filevaultEnabled: probeResults.filevault.value,
            icloudSignedIn: probeResults.icloud.signedIn,
            icloudDriveEnabled: probeResults.icloud.driveEnabled,
            icloudKeychainEnabled: probeResults.icloud.keychainEnabled
        )
    }

    private func makeScanResult(
        applications: [Application], modules: ScanModuleCollection,
        hostPosture: HostPostureCollection, errors: [CollectionError]
    ) -> ScanResult {
        ScanResult(
            metadata: makeMetadata(),
            elevation: ElevationInfo(isRoot: getuid() == 0, hasFda: detectFDA()),
            collections: makeCollections(applications: applications, modules: modules),
            hostPosture: makeHostPosture(from: hostPosture, modules: modules),
            errors: errors
        )
    }

    private func makeMetadata() -> ScanResult.Metadata {
        ScanResult.Metadata(
            scanId: UUID().uuidString,
            timestamp: ISO8601DateFormatter().string(from: Date()),
            hostname: ProcessInfo.processInfo.hostName,
            macosVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            collectorVersion: RootstockCommand.collectorVersion
        )
    }

    private func makeCollections(
        applications: [Application],
        modules: ScanModuleCollection
    ) -> ScanResult.Collections {
        ScanResult.Collections(
            core: makeCoreCollections(applications: applications, modules: modules),
            accountAccess: makeAccountAccessCollections(modules),
            system: makeSystemCollections(applications: applications, modules: modules)
        )
    }

    private func makeCoreCollections(
        applications: [Application],
        modules: ScanModuleCollection
    ) -> ScanResult.CoreCollections {
        ScanResult.CoreCollections(
            applications: applications,
            tccGrants: modules.tccGrants,
            xpcServices: modules.xpcServices,
            keychainAcls: modules.keychainAcls,
            mdmProfiles: modules.mdmProfiles,
            launchItems: modules.launchItems
        )
    }

    private func makeAccountAccessCollections(
        _ modules: ScanModuleCollection
    ) -> ScanResult.AccountAccessCollections {
        ScanResult.AccountAccessCollections(
            localGroups: modules.groupCollection.localGroups + modules.activeDirectory.localGroups,
            remoteAccessServices: modules.remoteAccessServices,
            firewallStatus: modules.firewallStatus,
            loginSessions: modules.loginSessions,
            authorization: ScanResult.AuthorizationCollections(
                authorizationRights: modules.authorizationRights,
                authorizationPlugins: modules.authorizationPlugins,
                systemExtensions: modules.systemExtensions
            ),
            sudoersRules: modules.sudoersRules
        )
    }

    private func makeSystemCollections(
        applications: [Application],
        modules: ScanModuleCollection
    ) -> ScanResult.SystemCollections {
        ScanResult.SystemCollections(
            runningProcesses: modules.runningProcesses,
            userDetails: modules.groupCollection.userDetails + modules.activeDirectory.userDetails,
            fileAcls: modules.fileAcls,
            bluetoothDevices: modules.physicalSecurity.bluetoothDevices,
            adBinding: modules.activeDirectory.binding,
            kerberosArtifacts: modules.kerberosArtifacts,
            sandboxProfiles: applications.compactMap(\.sandboxProfile)
        )
    }

    private func makeHostPosture(
        from hostPosture: HostPostureCollection,
        modules: ScanModuleCollection
    ) -> ScanResult.HostPosture {
        ScanResult.HostPosture(
            gatekeeperEnabled: hostPosture.gatekeeperEnabled,
            sipEnabled: hostPosture.sipEnabled,
            filevaultEnabled: hostPosture.filevaultEnabled,
            physicalSecurity: makePhysicalSecurity(from: modules.physicalSecurity),
            icloud: ScanResult.ICloud(
                icloudSignedIn: hostPosture.icloudSignedIn,
                icloudDriveEnabled: hostPosture.icloudDriveEnabled,
                icloudKeychainEnabled: hostPosture.icloudKeychainEnabled
            )
        )
    }

    private func makePhysicalSecurity(
        from physicalSecurity: PhysicalSecurityCollection
    ) -> ScanResult.PhysicalSecurity {
        ScanResult.PhysicalSecurity(
            device: ScanResult.DeviceSecurity(
                lockdownModeEnabled: physicalSecurity.lockdownModeEnabled,
                bluetoothEnabled: physicalSecurity.bluetoothEnabled,
                bluetoothDiscoverable: physicalSecurity.bluetoothDiscoverable
            ),
            screen: ScanResult.ScreenSecurity(
                screenLockEnabled: physicalSecurity.screenLockEnabled,
                screenLockDelay: physicalSecurity.screenLockDelay,
                displaySleepTimeout: physicalSecurity.displaySleepTimeout
            ),
            boot: ScanResult.BootSecurity(
                thunderboltSecurityLevel: physicalSecurity.thunderboltSecurityLevel,
                secureBootLevel: physicalSecurity.secureBootLevel,
                externalBootAllowed: physicalSecurity.externalBootAllowed
            )
        )
    }

    static func mergeApplicationEnrichments(
        sandboxApplications: [Application],
        quarantineApplications: [Application]
    ) -> [Application] {
        var quarantineInfoByPath: [String: QuarantineInfo] = [:]
        for app in quarantineApplications {
            if let info = app.quarantineInfo {
                quarantineInfoByPath[app.path] = info
            }
        }

        return sandboxApplications.map { app in
            guard let quarantineInfo = quarantineInfoByPath[app.path] else { return app }
            return app.with(quarantineInfo: quarantineInfo)
        }
    }

    /// Detects Full Disk Access by attempting to read the system TCC database.
    private func detectFDA() -> Bool {
        TCCAccessProbe.canQueryDatabase(at: TCCAccessProbe.systemDatabasePath)
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
