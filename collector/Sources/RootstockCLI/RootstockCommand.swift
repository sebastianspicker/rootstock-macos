import ArgumentParser
import Foundation
import Models
import TCC
import Entitlements
import CodeSigning
import Export

@main
struct RootstockCommand: AsyncParsableCommand {
    static let collectorVersion = "1.0.0"

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
        let orchestrator = ScanOrchestrator(verbose: verbose)
        let result = await orchestrator.run(config: config)

        let exporter = JSONExporter()
        try exporter.write(result, to: output, force: force)

        for line in Self.completionLines(for: result, output: output) {
            print(line)
        }
    }

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
            lines.append("Error: \(errorCount) error(s), \(warningCount) warning(s) — scan failed; see 'errors' in output for details")
        } else if warningCount > 0 {
            lines.append("⚠ \(warningCount) warning(s) — scan is partial; see 'errors' in output for details")
        }
        return lines
    }
}
