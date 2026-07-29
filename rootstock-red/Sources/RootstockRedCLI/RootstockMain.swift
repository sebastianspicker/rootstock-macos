/// rootstock-red CLI: assess-first audit, list collectors/vectors/checks, and report writers.
/// Default product is read-only assessment; lab actions live in the separate rootstock-red-lab product.
import ArgumentParser
import Foundation
import RootstockCore
import MacEnumKit
import MacVulnKit
import MacOpsecKit
import MacArtifactKit
import MacReportKit

@main
struct RootstockRed: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rootstock-red",
        abstract: "Assess-first macOS security research platform (authorized use only).",
        discussion: """
        Default mode is read-only assessment. Lab/agent packages are not linked into this build.
        See ACCEPTABLE_USE.md and docs/ for architecture and non-goals.
        """,
        version: "\(RootstockCore.version) (schema \(RootstockCore.schemaVersion))",
        subcommands: [
            AuditCommand.self,
            EnumCommand.self,
            ReportCommand.self,
            ExportFamilyCommand.self,
            LabCommand.self,
            ListCommand.self,
            VersionCommand.self,
        ],
        defaultSubcommand: nil
    )
}

// MARK: - Shared options

struct GlobalConsentOptions: ParsableArguments {
    @Flag(name: .customLong("i-am-authorized"), help: "Confirm authorized engagement (required for lab).")
    var iAmAuthorized = false

    @Option(name: .long, help: "Engagement scope ID (e.g. ENG-203).")
    var scope: String?

    @Option(name: .customLong("operator"), help: "Operator name for audit log.")
    var operatorName: String?
}

// MARK: - audit

struct AuditCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "audit",
        abstract: "Run read-only collectors and checks (assess mode)."
    )

    @Option(name: .long, help: "Scan profile: quick|standard|deep|paranoid")
    var profile: String = ScanProfile.standard.rawValue

    @Option(name: .long, help: "Output format: json|jsonl|sarif|md")
    var format: String = ReportFormat.json.rawValue

    @Option(name: .long, help: "Write report to this file path.")
    var output: String?

    @Option(name: .long, help: "Offline project directory for findings/state/audit.")
    var project: String?

    @Flag(name: .long, help: "Allow network egress (default: off in assess).")
    var allowNetwork = false

    @OptionGroup var consent: GlobalConsentOptions

    func run() async throws {
        try SafetyRails.ensureNotDisabled()
        let options = try validatedOptions()
        let assessment = await performAssessment(options)
        let auditURL = try await persistAudit(assessment, options: options)
        try await persistProject(assessment, options: options)

        try writeReport(assessment, format: options.reportFormat)

        FileHandle.standardError.write(
            Data(
                "Rootstock Red assess complete: \(assessment.findings.count) findings; audit: \(auditURL.path)\n".utf8
            )
        )
    }
}

private extension AuditCommand {
    struct ValidatedOptions {
        let scanProfile: ScanProfile
        let reportFormat: ReportFormat
        let projectURL: URL?
        let context: EvaluationContext
    }

    struct Assessment {
        let state: CollectedState
        let findings: [Finding]
        let registry: ModuleRegistry
        let ledger: ArtifactLedger
    }

    func validatedOptions() throws -> ValidatedOptions {
        guard let scanProfile = ScanProfile(rawValue: profile) else {
            throw RootstockError.invalidArgument("Unknown profile: \(profile)")
        }
        guard let reportFormat = ReportFormat(rawValue: format) else {
            throw RootstockError.invalidArgument("Unknown format: \(format)")
        }
        let projectURL = project.map { URL(fileURLWithPath: $0) }
        let tokens = ConsentTokens(
            iAmAuthorized: consent.iAmAuthorized,
            scope: consent.scope,
            operatorName: consent.operatorName
        )
        let context = EvaluationContext.assess(
            profile: scanProfile,
            allowNetwork: allowNetwork,
            consent: tokens,
            projectDirectory: projectURL
        )
        return ValidatedOptions(
            scanProfile: scanProfile,
            reportFormat: reportFormat,
            projectURL: projectURL,
            context: context
        )
    }

    func performAssessment(_ options: ValidatedOptions) async -> Assessment {
        let registry = VulnModuleRegistry.fullRegistry()
        let ledger = ArtifactLedger()
        await ledger.record(path: "assessment", action: "start")
        let state = await CollectionRunner.run(registry: registry, context: options.context)
        await ledger.recordStatePaths(state)
        let rawFindings = await CheckRunner.run(
            registry: registry,
            state: state,
            context: options.context
        )
        return Assessment(
            state: state,
            findings: OpsecScorer().annotateAll(rawFindings),
            registry: registry,
            ledger: ledger
        )
    }

    func persistAudit(
        _ assessment: Assessment,
        options: ValidatedOptions
    ) async throws -> URL {
        let auditURL = try AuditLog.defaultURL(projectDirectory: options.projectURL)
        let audit = AuditLog(fileURL: auditURL)
        try await audit.append(
            AuditRecord(
                run: .init(
                    mode: .assess,
                    profile: options.scanProfile,
                    allowNetwork: allowNetwork
                ),
                subject: .init(
                    operatorName: consent.operatorName,
                    scope: consent.scope,
                    hostUUID: options.context.hostUUID,
                    argvSummary: "rootstock-red audit --profile \(profile) --format \(format)"
                ),
                outcome: .init(
                    findingCount: assessment.findings.count,
                    collectorIds: assessment.registry.collectorIds,
                    checkIds: assessment.registry.checkIds
                )
            )
        )
        return auditURL
    }

    func persistProject(
        _ assessment: Assessment,
        options: ValidatedOptions
    ) async throws {
        guard let projectURL = options.projectURL else { return }
        let bundle = ProjectBundle(directory: projectURL)
        try bundle.write(
            findings: assessment.findings,
            state: assessment.state,
            meta: [
                "profile": options.scanProfile.rawValue,
                "mode": RunMode.assess.rawValue,
            ]
        )
        let artifactsURL = projectURL.appendingPathComponent("artifacts.json")
        try await assessment.ledger.write(to: artifactsURL)
        FileHandle.standardError.write(Data("Project written to \(projectURL.path)\n".utf8))
    }

    func writeReport(
        _ assessment: Assessment,
        format: ReportFormat
    ) throws {
        let data = try ReportWriter.render(
            format: format,
            findings: assessment.findings,
            state: assessment.state
        )
        guard let output else {
            if let text = String(data: data, encoding: .utf8) {
                print(text)
            } else {
                FileHandle.standardOutput.write(data)
            }
            return
        }
        try data.write(to: URL(fileURLWithPath: output), options: .atomic)
        FileHandle.standardError.write(
            Data("Wrote \(assessment.findings.count) findings to \(output)\n".utf8)
        )
    }
}

// MARK: - enum

struct EnumCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "enum",
        abstract: "Run named collectors only and print CollectedState JSON."
    )

    @Argument(help: "Collector IDs (e.g. collect.host collect.launchd)")
    var collectorIds: [String]

    @Option(name: .long, help: "Scan profile")
    var profile: String = ScanProfile.standard.rawValue

    func run() async throws {
        try SafetyRails.ensureNotDisabled()
        guard let scanProfile = ScanProfile(rawValue: profile) else {
            throw RootstockError.invalidArgument("Unknown profile: \(profile)")
        }
        let context = EvaluationContext.assess(profile: scanProfile)
        let registry = VulnModuleRegistry.fullRegistry()
        let only = Set(collectorIds)
        let unknown = only.subtracting(Set(registry.collectorIds))
        if !unknown.isEmpty {
            throw RootstockError.invalidArgument(
                "Unknown collectors: \(unknown.sorted().joined(separator: ", "))"
            )
        }
        let state = await CollectionRunner.run(
            registry: registry,
            context: context,
            onlyIds: only
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(state)
        print(String(data: data, encoding: .utf8) ?? "{}")
    }
}

// MARK: - report

struct ReportCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "report",
        abstract: "Re-render findings.jsonl from a project directory."
    )

    @Option(name: .long, help: "Project directory containing findings.jsonl")
    var project: String

    @Option(name: .long, help: "Output format: json|jsonl|sarif|md")
    var format: String = ReportFormat.markdown.rawValue

    @Option(name: .long, help: "Optional output file")
    var output: String?

    func run() async throws {
        try SafetyRails.ensureNotDisabled()
        guard let reportFormat = ReportFormat(rawValue: format) else {
            throw RootstockError.invalidArgument("Unknown format: \(format)")
        }
        let projectURL = URL(fileURLWithPath: project)
        let findingsURL = projectURL.appendingPathComponent("findings.jsonl")
        let data = try Data(contentsOf: findingsURL)
        let text = String(data: data, encoding: .utf8) ?? ""
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var findings: [Finding] = []
        for line in text.split(separator: "\n") where !line.isEmpty {
            let lineData = Data(line.utf8)
            findings.append(try decoder.decode(Finding.self, from: lineData))
        }
        let out = try ReportWriter.render(format: reportFormat, findings: findings)
        if let output {
            try out.write(to: URL(fileURLWithPath: output), options: .atomic)
        } else if let s = String(data: out, encoding: .utf8) {
            print(s)
        }
    }
}

// MARK: - export-family (DD-011 open-export for Neo4j)

struct ExportFamilyCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "export-family",
        abstract: "Write optional family open-export JSON (schema v1) for graph import."
    )

    @Option(name: .long, help: "Project directory with findings.jsonl and optional state.json")
    var project: String?

    @Option(name: .long, help: "Output path for family-export.json")
    var output: String

    @Option(name: .long, help: "Scope name embedded in export metadata")
    var scope: String = "rootstock-red-assess"

    @Option(name: .long, help: "Scan profile label")
    var profile: String = ScanProfile.standard.rawValue

    func run() async throws {
        try SafetyRails.ensureNotDisabled()
        var findings: [Finding] = []
        var state = CollectedState()
        if let project {
            let projectURL = URL(fileURLWithPath: project)
            let findingsURL = projectURL.appendingPathComponent("findings.jsonl")
            let text = try String(contentsOf: findingsURL, encoding: .utf8)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            for line in text.split(separator: "\n") where !line.isEmpty {
                findings.append(try decoder.decode(Finding.self, from: Data(line.utf8)))
            }
            let stateURL = projectURL.appendingPathComponent("state.json")
            if FileManager.default.fileExists(atPath: stateURL.path) {
                let stateData = try Data(contentsOf: stateURL)
                state = try decoder.decode(CollectedState.self, from: stateData)
            }
        }
        let outURL = URL(fileURLWithPath: output)
        try FamilyOpenExporter.writeJSON(
            findings: findings,
            state: state,
            to: outURL,
            scopeName: scope,
            scanProfile: profile
        )
        FileHandle.standardError.write(
            Data("Wrote family open-export (\(findings.count) findings) to \(outURL.path)\n".utf8)
        )
    }
}

// MARK: - lab (fail closed)

struct LabCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "lab",
        abstract: "Lab actions (not compiled into default assess build).",
        subcommands: [LabPersistCommand.self]
    )
}

struct LabPersistCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "persist",
        abstract: "Persistence lab actions (fail closed in assess build)."
    )

    @Argument(help: "Action: install|status|remove")
    var action: String

    @OptionGroup var consent: GlobalConsentOptions

    @Flag(name: .customLong("no-dry-run"), help: "Disable dry-run (still fail closed in assess build).")
    var noDryRun = false

    @Option(name: .long, help: "Confirm token if required.")
    var confirm: String?

    func run() async throws {
        try SafetyRails.ensureNotDisabled()
        // Default product does not link RootstockLab.
        FileHandle.standardError.write(
            Data(
                """
                error: lab actions are not compiled into this assess build
                hint: Rootstock Red is assessment-first; see NOT_FOR_PRODUCTION_IMPLANT.md
                requested: lab persist \(action) dryRun=\(!noDryRun)
                consent: authorized=\(consent.iAmAuthorized) scope=\(consent.scope ?? "nil") operator=\(consent.operatorName ?? "nil")

                """.utf8
            )
        )
        throw ExitCode(2)
    }
}

// MARK: - list

struct ListCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "List registered collectors, checks, or attack-vector checks."
    )

    @Argument(help: "What to list: collectors|checks|vectors")
    var kind: String

    func run() async throws {
        let registry = VulnModuleRegistry.fullRegistry()
        switch kind {
        case "collectors":
            for id in registry.collectorIds.sorted() {
                print(id)
            }
        case "checks":
            for id in registry.checkIds.sorted() {
                print(id)
            }
        case "vectors":
            // Attack vector plane: check IDs prefixed rootstock.vector.
            let vectorPrefix = "rootstock.vector."
            for id in registry.checkIds.sorted() where id.hasPrefix(vectorPrefix) {
                print(id)
            }
        default:
            throw RootstockError.invalidArgument("Use: rootstock-red list collectors|checks|vectors")
        }
    }
}

// MARK: - version

struct VersionCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "version",
        abstract: "Print Rootstock Red and schema versions."
    )

    func run() async throws {
        print("rootstock-red \(RootstockCore.version)")
        print("schema \(RootstockCore.schemaVersion)")
        print("mode-default assess")
        print("lab-linked false")
        print("lab-product: rootstock-red-lab (separate)")
        print("agent-linked false")
    }
}
