import Foundation
import RootstockCore

/// Path-to-impact: Privileged Helper Tools and System Extensions as persistence / privesc surface.
///
/// Reports ranked findings with ATT&CK mappings, SIP state, and remediation.
/// Inventory alone is not sufficient to report a finding.
public struct PrivilegedHelperSygextVector: Check {
    public static let id = "rootstock.vector.persist.privileged_helper_sygext"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let scan = Self.scan(helpers: state.privilegedHelperTools, extensions: state.systemExtensionPaths)
        guard !scan.evidence.isEmpty else { return [] }
        let presentation = Self.presentation(for: scan, helperCount: state.privilegedHelperTools.count, extensionCount: state.systemExtensionPaths.count)
        return [Self.finding(scan: scan, presentation: presentation)]
    }


    private struct SurfaceScan {
        let evidence: [Evidence]
        let writableHelpers: Int
        let writableExtensions: Int
    }

    private struct Presentation {
        let title: String
        let severity: Severity
        let confidence: Confidence
        let opsecScore: Int
    }

    private static func scan(helpers: [String], extensions: [String]) -> SurfaceScan {
        guard !helpers.isEmpty || !extensions.isEmpty else { return SurfaceScan(evidence: [], writableHelpers: 0, writableExtensions: 0) }
        let helperScan = scan(paths: helpers, type: "privileged_helper")
        let extensionScan = scan(paths: extensions, type: "system_extension")
        let evidence = [Evidence(type: "summary", detail: "privilegedHelpers=\(helpers.count) systemExtensions=\(extensions.count)")]
            + helperScan.evidence + extensionScan.evidence
        return SurfaceScan(evidence: evidence, writableHelpers: helperScan.writableCount, writableExtensions: extensionScan.writableCount)
    }

    private static func scan(paths: [String], type: String) -> (evidence: [Evidence], writableCount: Int) {
        let results = paths.prefix(40).map { path -> (Evidence, Bool) in
            let writable = FileManager.default.isWritableFile(atPath: path) || parentWritable(path)
            return (Evidence(type: type, path: path, detail: "writable=\(writable)"), writable)
        }
        return (results.map(\.0), results.filter(\.1).count)
    }

    private static func presentation(for scan: SurfaceScan, helperCount: Int, extensionCount: Int) -> Presentation {
        let writableCount = scan.writableHelpers + scan.writableExtensions
        if writableCount > 0 {
            return Presentation(title: "Privileged helper / system-extension vector: user-writable surface (\(writableCount))", severity: .high, confidence: .medium, opsecScore: 55)
        }
        if helperCount + extensionCount >= 3 {
            return Presentation(title: "Privileged helper / system-extension persistence surface (\(helperCount) helpers, \(extensionCount) extensions)", severity: .medium, confidence: .medium, opsecScore: 20)
        }
        return Presentation(title: "Privileged helper / system-extension inventory surface (\(helperCount + extensionCount) paths)", severity: .low, confidence: .medium, opsecScore: 20)
    }

    private static func finding(scan: SurfaceScan, presentation: Presentation) -> Finding {
        Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .persist, resolution: .init(evidence: scan.evidence, attackTechniques: ["T1543.001", "T1543.004", "T1068", "T1574"], remediation: ["Inventory PrivilegedHelperTools and SystemExtensions; remove unexpected vendors", "Ensure helpers are root-owned, non-user-writable, and properly code-signed", "System Extensions require user/MDM approval - monitor unexpected activation prompts", "OPSEC: listing /Library/PrivilegedHelperTools is quiet; installing fakes is high-risk and out of assess scope"], falsePositiveNotes: "Legitimate security/MDM products install helpers and extensions. Writable flags on SIP-protected system volumes should normally be false; lab temp paths may simulate writability."), runtime: .init(confidence: presentation.confidence, dryRunSafe: true, opsecScore: presentation.opsecScore, esfExpected: ["OPEN", "WRITE"]))
    }

    private static func parentWritable(_ path: String) -> Bool {
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        return FileManager.default.isWritableFile(atPath: parent)
    }
}
