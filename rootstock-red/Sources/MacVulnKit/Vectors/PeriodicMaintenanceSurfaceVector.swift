import Foundation
import RootstockCore

/// Path-to-impact: periodic / maintenance script directories as root-scheduled privesc surface.
///
/// Research basis: PEASS periodic checks; historical maintenance-script privesc research themes.
/// Safety and behavior: API-first path probes + collector notes; no root script planting; SIP honesty.
public struct PeriodicMaintenanceSurfaceVector: Check {
    public static let id = "rootstock.vector.privesc.periodic_maintenance_surface"
    public static let cost: CollectorCost = .low

    private static let probeDirs = [
        "/etc/periodic",
        "/private/etc/periodic",
        "/usr/local/etc/periodic",
        "/etc/periodic/daily",
        "/etc/periodic/weekly",
        "/etc/periodic/monthly",
        "/usr/local/etc/periodic/daily",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let analysis = Self.analyzePaths(in: state)
        guard analysis.shouldEmit else { return [] }
        return [Self.finding(for: analysis, protections: state.protections)]
    }

    private struct PathAnalysis {
        let present: [String]
        let writable: [String]
        let evidence: [Evidence]
        let forced: Bool

        var shouldEmit: Bool {
            !writable.isEmpty || present.contains { $0.contains("/usr/local/etc/periodic") } || forced
        }
    }

    private struct NotePaths {
        var present: [String] = []
        var writable: [String] = []
    }

    private struct ProbePaths {
        var present: [String] = []
        var writable: [String] = []
        var evidence: [Evidence] = []
    }

    private struct PeriodicPresentation {
        let title: String
        let severity: Severity
    }

    private static func analyzePaths(in state: CollectedState) -> PathAnalysis {
        let notePaths = pathsFromCollectorNotes(state.collectorNotes)
        let probes = probePaths()
        let present = Array(Set(notePaths.present + probes.present)).sorted()
        let writable = Array(Set(notePaths.writable + probes.writable)).sorted()
        return PathAnalysis(
            present: present,
            writable: writable,
            evidence: probes.evidence,
            forced: state.collectorNotes["privesc.periodic_paths"] != nil
        )
    }

    private static func pathsFromCollectorNotes(_ notes: [String: String]) -> NotePaths {
        guard let note = notes["privesc.periodic_paths"] else { return NotePaths() }
        return note.split(separator: "|").reduce(into: NotePaths()) { result, part in
            let path = String(part).trimmingCharacters(in: .whitespaces)
            guard !path.isEmpty else { return }
            result.present.append(path)
            if path.hasPrefix("writable:") {
                result.writable.append(String(path.dropFirst("writable:".count)))
            } else if FileManager.default.isWritableFile(atPath: path) {
                result.writable.append(path)
            }
        }
    }

    private static func probePaths() -> ProbePaths {
        let fileManager = FileManager.default
        return probeDirs.reduce(into: ProbePaths()) { result, path in
            var isDirectory: ObjCBool = false
            guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory) else { return }
            let isWritable = fileManager.isWritableFile(atPath: path)
            result.present.append(path)
            if isWritable { result.writable.append(path) }
            result.evidence.append(Evidence(type: "periodic_dir", path: path, detail: "dir=\(isDirectory.boolValue) writable=\(isWritable)"))
        }
    }

    private static func finding(for analysis: PathAnalysis, protections: ProtectionsState?) -> Finding {
        let customTree = analysis.present.contains { $0.contains("/usr/local/etc/periodic") }
        let sipDisabled = protections?.sipEnabled == false
        let presentation = periodicPresentation(writable: analysis.writable, sipDisabled: sipDisabled)
        var evidence = analysis.evidence
        evidence += analysis.writable.prefix(15).map { Evidence(type: "writable_periodic", path: $0, detail: "user-writable maintenance path") }
        if sipDisabled { evidence.append(Evidence(type: "sip_compound", detail: "SIP off compounds writable periodic paths")) }
        evidence.insert(Evidence(type: "summary", detail: "periodicPaths=\(analysis.present.count) writable=\(analysis.writable.count) customTree=\(customTree) (no scripts executed; no root plant)"), at: 0)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1053.003", "T1037", "T1068"], remediation: ["Ensure periodic directories are root-owned and not user-writable", "Review custom scripts under /usr/local/etc/periodic for unexpected content", "Prefer MDM/launchd over ad-hoc root periodic scripts", "OPSEC: assess lists paths only - planting periodic root scripts is lab-gated"], falsePositiveNotes: "Stock /etc/periodic trees are normal. Writable hits under lab/temp trees may be synthetic."), runtime: .init(confidence: analysis.writable.isEmpty ? .low : .medium, dryRunSafe: true, opsecScore: 20, esfExpected: ["OPEN", "WRITE"]))
    }

    private static func periodicPresentation(writable: [String], sipDisabled: Bool) -> PeriodicPresentation {
        if !writable.isEmpty && sipDisabled { return PeriodicPresentation(title: "Periodic maintenance vector: writable paths with SIP off (\(writable.count))", severity: .high) }
        if !writable.isEmpty { return PeriodicPresentation(title: "Periodic maintenance vector: user-writable scheduled-script paths (\(writable.count))", severity: .high) }
        return PeriodicPresentation(title: "Periodic / maintenance script surface (custom or forced inventory)", severity: .low)
    }
}
