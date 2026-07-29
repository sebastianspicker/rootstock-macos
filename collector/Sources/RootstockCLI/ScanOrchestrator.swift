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
struct ScanOrchestrator: Sendable {
    let verbose: Bool

    /// Runs independent collectors concurrently, then applies application
    /// enrichments in dependency order before assembling the stable scan schema.
    func run(config: ModuleConfig) async -> ScanResult {
        var allErrors: [CollectionError] = []
        let scanStart = Date()

        // Stage 1: Launch independent modules concurrently.
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
        let selectedModules = Self.independentModules.filter {
            config.includes($0.id)
        }
        async let dataSourceResultsTask = collectDataSourceResults(for: selectedModules)
        async let physicalSecurityTask = collectPhysicalSecurityIfIncluded(config)
        async let activeDirectoryTask = collectActiveDirectoryIfIncluded(config)

        return await ModuleTaskResults(
            dataSourceResults: dataSourceResultsTask,
            physicalSecurity: physicalSecurityTask,
            activeDirectory: activeDirectoryTask
        )
    }

    /// Registry entry for a collector that has no application-data dependency.
    ///
    /// The identifier must remain unique and compatible with `ModuleConfig`
    /// because completed tasks are stored and consumed by module ID.
    struct IndependentModule: Sendable {
        let id: RootstockModuleID
        private let collectData: @Sendable () async -> DataSourceResult

        init(
            id: RootstockModuleID,
            collectData: @escaping @Sendable () async -> DataSourceResult
        ) {
            self.id = id
            self.collectData = collectData
        }

        func collect() async -> DataSourceResult {
            await collectData()
        }
    }

    /// Extension seam for collectors that are safe to execute concurrently.
    static var independentModules: [IndependentModule] {
        [
            IndependentModule(id: .tcc) { await TCCDataSource().collect() },
            IndependentModule(id: .xpc) { await XPCDataSource().collect() },
            IndependentModule(id: .persistence) { await PersistenceDataSource().collect() },
            IndependentModule(id: .keychain) { await KeychainDataSource().collect() },
            IndependentModule(id: .mdm) { await MDMDataSource().collect() },
            IndependentModule(id: .groups) { await GroupDataSource().collect() },
            IndependentModule(id: .remoteAccess) { await RemoteAccessDataSource().collect() },
            IndependentModule(id: .firewall) { await FirewallDataSource().collect() },
            IndependentModule(id: .loginSessions) { await LoginSessionDataSource().collect() },
            IndependentModule(id: .authorizationDB) { await AuthorizationDBDataSource().collect() },
            IndependentModule(id: .authorizationPlugins) {
                await AuthorizationPluginDataSource().collect()
            },
            IndependentModule(id: .systemExtensions) {
                await SystemExtensionDataSource().collect()
            },
            IndependentModule(id: .sudoers) { await SudoersDataSource().collect() },
            IndependentModule(id: .fileACLs) { await FileACLDataSource().collect() },
            IndependentModule(id: .shellHooks) { await ShellHookDataSource().collect() },
            IndependentModule(id: .kerberos) { await KerberosArtifactDataSource().collect() },
        ]
    }

    static var independentModuleIDs: [RootstockModuleID] {
        independentModules.map(\.id)
    }

    private func collectDataSourceResults(
        for modules: [IndependentModule]
    ) async -> [RootstockModuleID: TimedDataSourceResult] {
        await withTaskGroup(
            of: (RootstockModuleID, TimedDataSourceResult).self,
            returning: [RootstockModuleID: TimedDataSourceResult].self
        ) { group in
            for module in modules {
                group.addTask {
                    (module.id, await self.timed { await module.collect() })
                }
            }

            var completedResults: [RootstockModuleID: TimedDataSourceResult] = [:]
            for await (moduleID, result) in group {
                completedResults[moduleID] = result
            }

            // Completion order is intentionally irrelevant: results are keyed by
            // module ID and consumed later through explicit, fixed ID lookups.
            return completedResults
        }
    }

    private func collectPhysicalSecurityIfIncluded(
        _ config: ModuleConfig
    ) async -> (PhysicalSecurityResult, Double)? {
        guard config.includes(.physicalSecurity) else { return nil }
        return await timed { await PhysicalSecurityDataSource().collectAll() }
    }

    private func collectActiveDirectoryIfIncluded(
        _ config: ModuleConfig
    ) async -> ((result: DataSourceResult, binding: ADBinding?), Double)? {
        guard config.includes(.activeDirectory) else { return nil }
        return await timed { ActiveDirectoryDataSource().collectWithBindingOutcome() }
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
            tccGrants: collectNodes(taskResults.result(for: .tcc), as: TCCGrant.self, label: "TCC", noun: "grants", errors: &errors),
            xpcServices: collectNodes(taskResults.result(for: .xpc), as: XPCService.self, label: "XPC", noun: "services", errors: &errors),
            keychainAcls: collectNodes(taskResults.result(for: .keychain), as: KeychainItem.self, label: "Keychain", noun: "items", errors: &errors),
            mdmProfiles: collectNodes(taskResults.result(for: .mdm), as: MDMProfile.self, label: "MDM", noun: "profiles", errors: &errors),
            launchItems: collectNodes(taskResults.result(for: .persistence), as: LaunchItem.self, label: "Persistence", noun: "items", errors: &errors),
            groupCollection: collectGroups(taskResults.result(for: .groups), errors: &errors),
            remoteAccessServices: collectNodes(taskResults.result(for: .remoteAccess), as: RemoteAccessService.self, label: "RemoteAccess", noun: "services", errors: &errors),
            firewallStatus: collectNodes(taskResults.result(for: .firewall), as: FirewallStatus.self, label: "Firewall", noun: "policies", errors: &errors),
            loginSessions: collectNodes(taskResults.result(for: .loginSessions), as: LoginSession.self, label: "Sessions", noun: "sessions", errors: &errors),
            authorizationRights: collectNodes(taskResults.result(for: .authorizationDB), as: AuthorizationRight.self, label: "AuthDB", noun: "rights", errors: &errors),
            authorizationPlugins: collectNodes(taskResults.result(for: .authorizationPlugins), as: AuthorizationPlugin.self, label: "AuthPlugins", noun: "plugins", errors: &errors),
            systemExtensions: collectNodes(taskResults.result(for: .systemExtensions), as: SystemExtension.self, label: "SysExt", noun: "extensions", errors: &errors),
            sudoersRules: collectNodes(taskResults.result(for: .sudoers), as: SudoersRule.self, label: "Sudoers", noun: "rules", errors: &errors),
            runningProcesses: await collectRunningProcesses(config: config, applications: applications, errors: &errors),
            fileAcls: collectFileACLs(taskResults.result(for: .fileACLs), shellHooks: taskResults.result(for: .shellHooks), errors: &errors),
            physicalSecurity: collectPhysicalSecurity(taskResults.physicalSecurity, errors: &errors),
            activeDirectory: collectActiveDirectory(taskResults.activeDirectory, errors: &errors),
            kerberosArtifacts: collectNodes(taskResults.result(for: .kerberos), as: KerberosArtifact.self, label: "Kerberos", noun: "artifacts", errors: &errors)
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
        _ timedResult: ((result: DataSourceResult, binding: ADBinding?), Double)?,
        errors: inout [CollectionError]
    ) -> ActiveDirectoryCollection {
        guard let (combined, elapsed) = timedResult else {
            return ActiveDirectoryCollection()
        }
        let users = combined.result.nodes.compactMap { $0 as? UserDetail }
        let groups = combined.result.nodes.compactMap { $0 as? LocalGroup }
        errors.append(contentsOf: combined.result.errors)
        if verbose {
            let bound = combined.binding.map { String($0.isBound) } ?? "unknown"
            err("  [AD]           completed in \(format(elapsed))  (bound: \(bound), \(users.count) AD users, \(groups.count) AD-sourced groups, \(combined.result.errors.count) errors)")
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
    func timed<T>(_ block: () async -> T) async -> (T, Double) {
        let start = Date()
        let result = await block()
        return (result, Date().timeIntervalSince(start))
    }

    /// Formats elapsed seconds as "X.XXs".
    func format(_ seconds: Double) -> String {
        String(format: "%.2fs", seconds)
    }

    /// Write a line to stderr.
    func err(_ text: String) {
        FileHandle.standardError.write(Data((text + "\n").utf8))
    }
}
