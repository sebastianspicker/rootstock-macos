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

    @Option(name: .shortAndLong, help: "Comma-separated modules to run: tcc, entitlements, codesigning, all.")
    var modules: String = "all"

    mutating func run() async throws {
        print("Rootstock Collector v\(Self.collectorVersion)")
        fflush(stdout)  // flush before stderr progress begins

        let config = ScanOrchestrator.ModuleConfig.from(modules)
        let orchestrator = ScanOrchestrator(verbose: verbose)
        let result = await orchestrator.run(config: config)

        let exporter = JSONExporter()
        try exporter.write(result, to: output)

        let entitlementCount = result.applications.flatMap(\.entitlements).count
        print("Scan complete. Found \(result.applications.count) app(s), \(result.tccGrants.count) TCC grant(s), \(entitlementCount) entitlement(s). Output: \(output)")

        if !result.errors.isEmpty {
            print("⚠ \(result.errors.count) warning(s) — see 'errors' in output for details")
        }
    }
}
