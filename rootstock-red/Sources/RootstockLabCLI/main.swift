import ArgumentParser
import Foundation
import RootstockCore
import RootstockLab

@main
struct RootstockLabCLI: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rootstock-red-lab",
        abstract: "Gated Rootstock Red lab actions (authorized pentest validation only).",
        discussion: """
        Separate from the default `rootstock-red` assess binary. Requires consent flags.
        Default is dry-run (no writes). Use --no-dry-run only on authorized lab hosts.
        No keylog, keychain dump, or C2. See ACCEPTABLE_USE.md.
        """,
        version: "\(RootstockCore.version) (schema \(RootstockCore.schemaVersion))",
        subcommands: [
            ListCommand.self,
            RunCommand.self,
            PersistCommand.self,
            SurfaceCommand.self,
            PlanAllCommand.self,
        ]
    )
}

// MARK: - Shared

struct LabConsentOptions: ParsableArguments {
    @Flag(name: .customLong("i-am-authorized"), help: "Confirm authorized engagement.")
    var iAmAuthorized = false

    @Option(name: .long, help: "Engagement scope ID (e.g. ENG).")
    var scope: String?

    @Option(name: .customLong("operator"), help: "Operator name for audit.")
    var operatorName: String?

    @Flag(name: .customLong("no-dry-run"), help: "Actually perform writes (default is dry-run).")
    var noDryRun = false

    @Option(name: .long, help: "Confirm token if action requires one.")
    var confirm: String?

    func tokens() -> ConsentTokens {
        ConsentTokens(
            iAmAuthorized: iAmAuthorized,
            scope: scope,
            operatorName: operatorName,
            confirm: confirm
        )
    }

    func makeContext() -> EvaluationContext {
        EvaluationContext(
            mode: .lab,
            profile: .standard,
            dryRun: !noDryRun,
            allowNetwork: false,
            consent: tokens()
        )
    }
}

func printJSON<T: Encodable>(_ value: T) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    let data = try encoder.encode(value)
    if let text = String(data: data, encoding: .utf8) {
        print(text)
    } else {
        FileHandle.standardOutput.write(data)
    }
}

// MARK: - list

struct ListCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "List registered lab action IDs."
    )

    func run() async throws {
        let ids = ActionRegistry.production().actionIds
        for id in ids {
            print(id)
        }
    }
}

// MARK: - run (generic lifecycle for any registered LabAction)

struct RunCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "run",
        abstract: "Run a registered lab action by ID (plan|install|status|remove)."
    )

    @Argument(help: "Lab action ID (see `list`).")
    var actionId: String

    @Argument(help: "Operation: plan|install|status|remove")
    var operation: String

    @Option(name: .long, help: "Shell RC file path (lab.persist.shellrc).")
    var rcFile: String?

    @Option(name: .customLong("lab-root"), help: "Lab root directory for marker-style actions.")
    var labRoot: String?

    @Option(name: .long, help: "App slug for surface markers.")
    var app: String?

    @Option(name: .long, help: "LaunchAgent label when applicable.")
    var label: String?

    @Option(name: .long, help: "Directory for LaunchAgent plists.")
    var directory: String?

    @OptionGroup var consent: LabConsentOptions

    func run() async throws {
        try SafetyRails.ensureNotDisabled()

        guard let op = LabOperation(rawValue: operation) else {
            throw RootstockError.invalidArgument(
                "Unknown operation: \(operation). Use plan|install|status|remove"
            )
        }

        var parameters: [String: String] = [:]
        if let rcFile { parameters["rcFile"] = rcFile }
        if let labRoot { parameters["labRoot"] = labRoot }
        if let app { parameters["app"] = app }
        if let label { parameters["label"] = label }
        if let directory { parameters["directory"] = directory }

        let request = LabActionRequest(
            actionId: actionId,
            operation: op,
            parameters: parameters
        )
        let pipeline = LabPipeline()
        let result = try await pipeline.run(request: request, context: consent.makeContext())
        try printJSON(result)
        if !result.success {
            throw ExitCode(1)
        }
    }
}

// MARK: - persist

struct PersistCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "persist",
        abstract: "LaunchAgent lab lifecycle (harmless plist marker)."
    )

    @Argument(help: "Operation: install|status|remove")
    var operation: String

    @Option(name: .long, help: "LaunchAgent Label (default com.rootstock.red.lab.marker).")
    var label: String = "com.rootstock.red.lab.marker"

    @Option(name: .long, help: "Directory for the plist (default ~/Library/LaunchAgents). Override in tests.")
    var directory: String?

    @OptionGroup var consent: LabConsentOptions

    func run() async throws {
        try SafetyRails.ensureNotDisabled()

        guard let op = LabOperation(rawValue: operation) else {
            throw RootstockError.invalidArgument(
                "Unknown operation: \(operation). Use install|status|remove"
            )
        }
        guard op == .install || op == .status || op == .remove else {
            throw RootstockError.invalidArgument("persist supports install|status|remove")
        }

        var parameters: [String: String] = ["label": label]
        if let directory {
            parameters["directory"] = directory
        }

        let request = LabActionRequest(
            actionId: LaunchAgentLabAction.id,
            operation: op,
            parameters: parameters
        )
        let pipeline = LabPipeline()
        let result = try await pipeline.run(request: request, context: consent.makeContext())
        try printJSON(result)
        if !result.success {
            throw ExitCode(1)
        }
    }
}

// MARK: - surface

struct SurfaceCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "surface",
        abstract: "Dylib surface lab (marker only; no binary patch)."
    )

    @Argument(help: "Operation: dylib-plan|dylib-apply|dylib-remove|dylib-status")
    var operation: String

    @Option(name: .customLong("lab-root"), help: "Lab root directory (default ~/Library/RootstockLab).")
    var labRoot: String?

    @Option(name: .long, help: "App slug for marker name (default generic).")
    var app: String = "generic"

    @OptionGroup var consent: LabConsentOptions

    func run() async throws {
        try SafetyRails.ensureNotDisabled()

        let op: LabOperation
        switch operation {
        case "dylib-plan", "plan":
            op = .plan
        case "dylib-apply", "apply", "install":
            op = .install
        case "dylib-remove", "remove":
            op = .remove
        case "dylib-status", "status":
            op = .status
        default:
            throw RootstockError.invalidArgument(
                "Unknown surface op: \(operation). Use dylib-plan|dylib-apply|dylib-remove|dylib-status"
            )
        }

        var parameters: [String: String] = ["app": app]
        if let labRoot {
            parameters["labRoot"] = labRoot
        }

        let request = LabActionRequest(
            actionId: DylibSurfaceLabAction.id,
            operation: op,
            parameters: parameters
        )
        let pipeline = LabPipeline()
        let result = try await pipeline.run(request: request, context: consent.makeContext())
        try printJSON(result)
        if !result.success {
            throw ExitCode(1)
        }
    }
}

// MARK: - plan-all

struct PlanAllCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "plan-all",
        abstract: "Dry-run plan for all registered lab actions (JSON)."
    )

    @OptionGroup var consent: LabConsentOptions

    func run() async throws {
        try SafetyRails.ensureNotDisabled()
        var context = consent.makeContext()
        context.dryRun = true
        // plan-all forces dry-run regardless of --no-dry-run
        let pipeline = LabPipeline()
        let results = try await pipeline.planAll(context: context)
        try printJSON(LabPlanAllResult(dryRun: true, results: results))
    }
}
