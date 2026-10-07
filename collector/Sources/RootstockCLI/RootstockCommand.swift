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
}
