import Foundation
import RootstockCore

/// Browser path metadata only - never opens history/cookie DBs.
public struct BrowserMetaPathsCheck: Check {
    public static let id = "rootstock.check.browser.meta_paths"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard !state.browserMeta.isEmpty else { return [] }
        let present = state.browserMeta.filter(\.exists)
        guard !present.isEmpty else {
            return [
                Finding(id: "\(Self.id).none", title: "No common browser paths present", severity: .info, category: .other, resolution: .init(evidence: [
                        Evidence(
                            type: "note",
                            detail: "Scanned \(state.browserMeta.count) browser path candidates; none exist"
                        ),
                    ], attackTechniques: ["T1217"], remediation: ["Informational - unusual on interactive user endpoints"]), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 5)),
            ]
        }

        return [
            Finding(id: Self.id, title: "Browser path metadata (\(present.count) present)", severity: .info, category: .other, resolution: .init(evidence: present.prefix(30).map { entry in
                    var detail = "\(entry.browser) kind=\(entry.kind)"
                    if let size = entry.sizeBytes {
                        detail += " sizeBytes=\(size)"
                    }
                    return Evidence(type: "browser_path", path: entry.path, detail: detail)
                }, attackTechniques: ["T1217"], remediation: [
                    "Metadata only - Rootstock Red does not open history/cookie databases in assess mode",
                    "Protect browser profiles with disk encryption and session hygiene",
                ], falsePositiveNotes: "Path presence does not imply credential exposure"), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 10, tccDomains: present.contains(where: {
                    $0.kind.contains("history") || $0.kind.contains("db")
                }) ? ["FullDiskAccess"] : [], esfExpected: ["OPEN"])),
        ]
    }
}
