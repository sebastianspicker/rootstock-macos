import ArgumentParser
import Foundation
import Models
import TCC
import Entitlements
import CodeSigning
import Export

/// Validates CLI input, runs the selected collectors, and writes one JSON scan.
///
/// Output replacement is deliberately narrow: `--force` may replace a regular
/// file, but the exporter always refuses symlinks.
@main
struct RootstockCommand: AsyncParsableCommand {
    static let collectorVersion = "0.1.0-alpha.1"

    static let configuration = CommandConfiguration(
        commandName: "rootstock-collector",
        abstract: "Rootstock macOS security metadata collector.",
        version: "rootstock-collector \(collectorVersion)"
    )

    @Option(name: .shortAndLong, help: "Output path for scan results (required).")
    var output: String

    @Flag(name: .shortAndLong, help: "Enable verbose logging to stderr.")
    var verbose: Bool = false

    @Flag(help: "Replace an existing regular output file. Symlinks are always refused.")
    var force: Bool = false

    @Option(
        name: .shortAndLong,
        help: "Comma-separated modules to run, or all. Supported: \(ScanOrchestrator.ModuleConfig.supportedModuleHelp)."
    )
    var modules: String = "all"

    mutating func run() async throws {
        print("Rootstock Collector v\(Self.collectorVersion)")
        fflush(stdout)  // flush before stderr progress begins

        let config: ScanOrchestrator.ModuleConfig
        do {
            config = try ScanOrchestrator.ModuleConfig.from(modules)
        } catch let error as RootstockModuleConfigError {
            throw ValidationError(error.description)
        }
        try Self.validateOutputPath(output, force: force)
        let orchestrator = ScanOrchestrator(verbose: verbose)
        let result = await orchestrator.run(config: config)

        let exporter = JSONExporter()
        try exporter.write(result, to: output, force: force)

        for line in Self.completionLines(for: result, output: output) {
            print(line)
        }
        for line in Self.coverageSummaryLines(for: result.errors) {
            print(line)
        }

        // A narrow --modules run can legitimately collect little; only a full run is judged.
        if modules == "all", Self.collectedNothing(result) {
            FileHandle.standardError.write(Data(
                "Error: every data source failed and no data was collected; partial scan written to \(output)\n".utf8
            ))
            throw ExitCode.failure
        }
    }

    /// Fails fast, before the scan starts, when the output location is unusable.
    /// The exporter repeats the authoritative checks when it writes.
    static func validateOutputPath(_ path: String, force: Bool) throws {
        let fileManager = FileManager.default
        let directory = URL(fileURLWithPath: path).deletingLastPathComponent().path
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: directory, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw ValidationError("Output directory does not exist: \(directory)")
        }
        guard fileManager.isWritableFile(atPath: directory) else {
            throw ValidationError("Output directory is not writable: \(directory)")
        }
        if fileManager.fileExists(atPath: path), !force {
            throw ValidationError("Output file already exists: \(path). Re-run with --force to replace it.")
        }
    }

    /// True when collection reported errors and produced no records at all.
    static func collectedNothing(_ result: ScanResult) -> Bool {
        guard !result.errors.isEmpty, result.adBinding == nil else { return false }
        let counts: [Int] = [
            result.applications.count, result.localGroups.count, result.runningProcesses.count,
            result.tccGrants.count, result.remoteAccessServices.count, result.userDetails.count,
            result.xpcServices.count, result.firewallStatus.count, result.fileAcls.count,
            result.keychainAcls.count, result.loginSessions.count, result.bluetoothDevices.count,
            result.mdmProfiles.count, result.authorizationRights.count, result.launchItems.count,
            result.authorizationPlugins.count, result.kerberosArtifacts.count,
            result.systemExtensions.count, result.sandboxProfiles.count, result.sudoersRules.count,
            result.networkListeners.count, result.certificateTrustSettings.count,
            result.browserExtensions.count, result.installedPackages.count,
        ]
        return counts.allSatisfy { $0 == 0 }
    }

    /// Classifies recoverable collection errors as partial output and any
    /// non-recoverable error as a failed scan while preserving the JSON evidence.
    static func completionLines(for result: ScanResult, output: String) -> [String] {
        let entitlementCount = result.applications.flatMap(\.entitlements).count
        let warningCount = result.errors.filter(\.recoverable).count
        let errorCount = result.errors.count - warningCount
        let status: String
        if errorCount > 0 {
            status = "failed"
        } else {
            status = result.errors.isEmpty ? "complete" : "partial"
        }
        var lines = [
            "Scan \(status). Found \(result.applications.count) app(s), \(result.tccGrants.count) TCC grant(s), \(entitlementCount) entitlement(s). Output: \(output)"
        ]

        if errorCount > 0 {
            lines.append("Error: \(errorCount) error(s), \(warningCount) warning(s) - scan failed; see 'errors' in output for details")
        } else if warningCount > 0 {
            lines.append("⚠ \(warningCount) warning(s) - scan is partial; see 'errors' in output for details")
        }
        return lines
    }

    private static let fullDiskAccessHint =
        "TCC.db could not be opened. Grant Full Disk Access to the terminal app that runs rootstock-collector "
        + "(System Settings → Privacy & Security → Full Disk Access), then rerun. "
        + "Without it no permission grants are collected."
    private static let sudoHint =
        "requires root: rerun with sudo to collect sudoers rules, per-user crontabs and the login-item database (sfltool)."
    private static let launchctlListHint =
        "`launchctl list` needs the logged-in user's GUI session, so the loaded state of LaunchAgents is "
        + "unknown; rerun in a normal terminal. Sudoers rules, per-user crontabs and the login-item "
        + "database (sfltool) additionally need sudo."
    private static let entitlementHint =
        "Entitlement extraction returned nothing for every app; if this persists outside a sandbox, run "
        + "`codesign -d --entitlements - --xml /Applications/Safari.app` manually and report the output."
    /// Closing action per source when no message-specific hint applies.
    private static let sourceHints: [String: String] = [
        "Firewall": "Firewall state unknown; check `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`.",
        "Network Listeners": "netstat and ps need no privilege; a failure means socket listing was blocked "
            + "(sandbox or endpoint policy). Check `netstat -anv -p tcp` in a normal terminal.",
        "Trust Settings": "Trust settings are read through the logged-in user's security session; run the "
            + "collector as that user in a GUI session (not over ssh, in a sandbox or under sudo).",
        "Browser Extensions": "Browser profiles live in the user's ~/Library/Application Support; run as the "
            + "logged-in user (grant Full Disk Access if a browser folder is protected). pluginkit needs the GUI session.",
        "Installed Packages": "/var/db/receipts is world-readable and needs no privilege; a failure points to a "
            + "damaged or oversized receipt plist.",
        "Host Posture": "Posture probes (spctl, csrutil, fdesetup, dscl, `launchctl print system`, scutil) need no "
            + "privilege; a failure means the tool was blocked or unavailable in this session.",
        "System Extensions": "systemextensionsctl and `kmutil showloaded` need no privilege; a failure means the "
            + "tool was blocked or unavailable in this session.",
    ]
    private static let maxCoverageGroups = 12

    /// Groups collection errors by source and attaches a remediation hint where one is known.
    static func coverageSummaryLines(for errors: [CollectionError]) -> [String] {
        guard !errors.isEmpty else { return [] }
        let groups = Dictionary(grouping: errors, by: \.source)
        let ordered = groups.sorted {
            $0.value.count != $1.value.count ? $0.value.count > $1.value.count : $0.key < $1.key
        }
        var lines = [
            "Coverage gaps (\(errors.count) warnings across \(groups.count) sources):"
        ]
        for (source, group) in ordered.prefix(maxCoverageGroups) {
            let hint = coverageHint(source: source, messages: group.map(\.message), count: group.count)
            let line = "  \(source) (\(group.count)) – \(hint)"
            if line.count <= 160 {
                lines.append(line)
            } else {
                lines.append("  \(source) (\(group.count)) –")
                lines.append("    \(hint)")
            }
        }
        if ordered.count > maxCoverageGroups {
            lines.append("  … and \(ordered.count - maxCoverageGroups) more sources")
        }
        return lines
    }

    private static func coverageHint(source: String, messages: [String], count: Int) -> String {
        let lowered = messages.map { $0.lowercased() }
        func any(_ needles: [String]) -> Bool {
            lowered.contains { message in needles.contains { message.contains($0) } }
        }
        let tccMentioned = source == "TCC Database" || any(["tcc.db"])
        if tccMentioned, any(["unable to open", "authorization denied", "full disk access"]) {
            return fullDiskAccessHint
        }
        if source == "Persistence", any(["launchctl list failed"]) {
            return launchctlListHint
        }
        if any(["requires root", "requires elevation", "sfltool dumpbtm failed",
                "error obtaining right system.privilege.admin", "bputil"]) {
            return sudoHint
        }
        if any(["codesign may not be working", "invalid entitlements blob"]) {
            return entitlementHint
        }
        if source == "Quarantine", any(["quarantine events database"]) {
            return "The quarantine events database is in the user's ~/Library/Preferences; run as the "
                + "logged-in user (Full Disk Access if protected) to resolve download origins."
        }
        return sourceHints[source] ?? "\(count) warning(s); see 'errors' in the output."
    }
}
