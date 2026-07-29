import Foundation
import RootstockBlueCase
import RootstockBlueCore
import RootstockBlueDetect
import RootstockBlueFX

extension RootstockBlueCLI {
    static func handleIR(_ args: [String]) throws {
        guard let sub = args.first else {
            throw RootstockBlueError.io("usage: ir posture|harden|triage ...")
        }
        switch sub {
        case "posture": try handleIRPosture(Array(args.dropFirst()))
        case "harden": try handleIRHarden(Array(args.dropFirst()))
        case "triage": try handleIRTriage(Array(args.dropFirst()))
        default:
            throw RootstockBlueError.io("usage: ir posture|harden --case <path> [--source <tree>] [--live] | ir triage --case <path> --source <tree>")
        }
    }

    static func handleIRPosture(_ args: [String]) throws {
        let pkg = try casePackage(from: args, usage: "ir posture requires --case <path.rsbcase>")
        let result = try postureResult(args)
        let count = try HostIRPosture.writeToCase(result.events, package: pkg, mode: result.mode)
        print("ir_posture mode=\(result.mode) events_written=\(count)")
        for event in result.events.prefix(20) {
            let summary = event.fields["security.product"]
                ?? event.fields["host.os_version"]
                ?? event.fields["protection.name"]
                ?? event.eventType
            print("  \(event.eventType) \(summary)")
        }
    }

    /// Hardening / defense assessment with structured remediation (live or offline).
    static func handleIRHarden(_ args: [String]) throws {
        let pkg = try casePackage(from: args, usage: "ir harden requires --case <path.rsbcase> [--source <tree>] [--live]")
        let result = try hardeningResult(args)
        let count = try HardeningAssessment.writeToCase(result.findings, package: pkg, mode: result.mode)
        let failures = result.findings.filter { $0.status == "fail" }.count
        let warnings = result.findings.filter { $0.status == "warn" }.count
        print("ir_harden mode=\(result.mode) findings=\(count) fail=\(failures) warn=\(warnings)")
        for finding in result.findings {
            print("  [\(finding.severity)/\(finding.status)] \(finding.control): \(finding.title)")
            if finding.status == "fail" || finding.status == "warn" {
                print("    remediation: \(finding.remediation)")
            }
        }
    }

    /// Full offline IR loop: parse → posture → harden → persistence inventory → detect.
    static func handleIRTriage(_ args: [String]) throws {
        let options = try TriageOptions(args: args)
        let result = try TriageRun(options: options)
        result.printSummary()
    }

    private static func casePackage(from args: [String], usage: String) throws -> CasePackage {
        guard let index = args.firstIndex(of: "--case"), args.count > index + 1 else {
            throw RootstockBlueError.io(usage)
        }
        return try CasePackage.open(at: URL(fileURLWithPath: args[index + 1]))
    }

    private static func postureResult(_ args: [String]) throws -> (events: [EventEnvelope], mode: String) {
        if let index = args.firstIndex(of: "--source"), args.count > index + 1 {
            let source = ImageSource.infer(from: URL(fileURLWithPath: args[index + 1]))
            return (try HostIRPosture.enumerateOffline(source: source), "offline")
        }
        return (HostIRPosture.enumerateLive(runStatusProbes: true), "live")
    }

    private static func hardeningResult(_ args: [String]) throws -> (findings: [HardeningAssessment.Finding], mode: String) {
        if let index = args.firstIndex(of: "--source"), args.count > index + 1 {
            let source = ImageSource.infer(from: URL(fileURLWithPath: args[index + 1]))
            return (try HardeningAssessment.assessOffline(source: source), "offline")
        }
        return (HardeningAssessment.assessLive(runStatusProbes: true), "live")
    }
}

private struct TriageOptions {
    let package: CasePackage
    let source: ImageSource
    let contentRoot: URL

    init(args: [String]) throws {
        guard let caseIndex = args.firstIndex(of: "--case"), args.count > caseIndex + 1 else {
            throw RootstockBlueError.io("usage: ir triage --case <path.rsbcase> --source <tree> [--content-root PATH] [--offline]")
        }
        guard let sourceIndex = args.firstIndex(of: "--source"), args.count > sourceIndex + 1 else {
            throw RootstockBlueError.io("ir triage requires --source <artifact-tree>")
        }
        package = try CasePackage.open(at: URL(fileURLWithPath: args[caseIndex + 1]))
        source = ImageSource.infer(from: URL(fileURLWithPath: args[sourceIndex + 1]))
        contentRoot = TriageOptions.contentRoot(from: args)
    }

    private static func contentRoot(from args: [String]) -> URL {
        guard let index = args.firstIndex(of: "--content-root"), args.count > index + 1 else {
            return RootstockBlueCLI.repoContentRoot()
        }
        return URL(fileURLWithPath: args[index + 1])
    }
}

private struct TriageRun {
    let parsed: Int
    let postureCount: Int
    let hardeningCount: Int
    let hardeningFindings: [HardeningAssessment.Finding]
    let persistenceCount: Int
    let persistenceSummary: [String: Int]
    let timeline: [EventEnvelope]
    let findings: [Finding]

    init(options: TriageOptions) throws {
        parsed = try ForensicsEngine().parse(source: options.source, into: options.package)
        let posture = try HostIRPosture.enumerateOffline(source: options.source)
        postureCount = try HostIRPosture.writeToCase(posture, package: options.package, mode: "offline")
        hardeningFindings = try HardeningAssessment.assessOffline(source: options.source)
        hardeningCount = try HardeningAssessment.writeToCase(hardeningFindings, package: options.package, mode: "offline")
        let inventory = try PersistenceInventory.enumerate(source: options.source)
        persistenceCount = try PersistenceInventory.writeToCase(inventory, package: options.package)
        persistenceSummary = PersistenceInventory.summarize(inventory)
        timeline = try CaseTimeline.merged(from: options.package)
        findings = try TriageRun.evaluateFindings(timeline: timeline, contentRoot: options.contentRoot)
    }

    func printSummary() {
        print("ir_triage mode=offline")
        let hardeningFailures = hardeningFindings.filter { $0.status == "fail" }.count
        print("parsed=\(parsed) posture=\(postureCount) harden=\(hardeningCount) harden_fail=\(hardeningFailures) persistence=\(persistenceCount) timeline=\(timeline.count) findings=\(findings.count)")
        printPersistenceSummary()
        printWavePluginSummary()
        printHardeningFindings()
        printDetectionFindings()
    }

    private static func evaluateFindings(timeline: [EventEnvelope], contentRoot: URL) throws -> [Finding] {
        let rulesDirectory = contentRoot.appendingPathComponent("detections/samples")
        guard FileManager.default.fileExists(atPath: rulesDirectory.path) else { return [] }
        return try DetectionEngine().evaluate(rulesDirectory: rulesDirectory, events: timeline)
    }

    private func printPersistenceSummary() {
        guard !persistenceSummary.isEmpty else { return }
        let kinds = persistenceSummary.keys.sorted().map { "\($0)=\(persistenceSummary[$0] ?? 0)" }.joined(separator: " ")
        print("persistence_kinds \(kinds)")
    }

    private func printWavePluginSummary() {
        let wavePlugins = ["SHELLPROFILES", "EMOND", "SUDOERS", "LAUNCHDOVERRIDES", "HARDEN", "PRIVHELPERS", "FOLDERACTIONS", "LOGINHOOKS", "AUTHPLUGINS", "NETUSAGE", "USBHISTORY", "KEYCHAINMETA", "CODESIGN", "ARD", "SPOTLIGHT", "TRASH", "DOCREVISIONS", "SAVEDSTATE", "FIREFOX", "NOTIFICATIONS", "QUICKLOOK", "SCREENTIME", "ICLOUD"]
        let counts = timeline.reduce(into: [String: Int]()) { counts, event in
            if wavePlugins.contains(event.sourcePlugin) { counts[event.sourcePlugin, default: 0] += 1 }
        }
        guard !counts.isEmpty else { return }
        let parts = counts.keys.sorted().map { "\($0)=\(counts[$0] ?? 0)" }.joined(separator: " ")
        print("wave_plugins \(parts)")
    }

    private func printHardeningFindings() {
        for finding in hardeningFindings.filter({ $0.status == "fail" || $0.status == "warn" }).prefix(15) {
            print("harden [\(finding.severity)/\(finding.status)] \(finding.control): \(finding.title)")
        }
    }

    private func printDetectionFindings() {
        for finding in findings.prefix(30) { print("- [\(finding.severity)] \(finding.ruleID): \(finding.title)") }
        if findings.isEmpty { print("note: zero findings on case timeline (rules may need field alignment)") }
    }
}
