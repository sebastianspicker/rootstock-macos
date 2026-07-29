import Foundation
import RootstockCore

/// BTM / login-items evidence (metadata only).
public struct BTMLoginItemsCheck: Check {
    public static let id = "rootstock.check.persist.btm_loginitems"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let hasBTM = state.btmStorePresent == true || state.loginItems?.btmStorePresent == true
        let paths = !state.loginItemPaths.isEmpty
            ? state.loginItemPaths
            : (state.loginItems?.loginItemPaths ?? [])
        let notes = state.loginItems?.notes ?? []

        // Emit when collector produced loginItems state, btm flag, or paths.
        guard state.loginItems != nil || state.btmStorePresent != nil || !paths.isEmpty else {
            return []
        }

        var evidence: [Evidence] = []
        evidence.append(
            Evidence(type: "btm", detail: "btmStorePresent=\(hasBTM)")
        )
        if let dir = state.loginItems?.btmDirectoryPath {
            let size = state.loginItems?.btmDirectorySizeBytes.map(String.init) ?? "unknown"
            evidence.append(
                Evidence(type: "btm_dir", path: dir, detail: "sizeBytes=\(size)")
            )
        }
        if let btmPath = state.loginItems?.backgroundItemsBtmPath {
            let size = state.loginItems?.backgroundItemsBtmSizeBytes.map(String.init) ?? "unknown"
            evidence.append(
                Evidence(type: "backgrounditems", path: btmPath, detail: "sizeBytes=\(size)")
            )
        }
        for path in paths.prefix(25) {
            evidence.append(Evidence(type: "login_item_path", path: path, detail: "path present"))
        }
        evidence.append(contentsOf: notes.prefix(10).map { Evidence(type: "note", detail: $0) })

        let title: String
        if hasBTM {
            title = "BTM / login-items store evidence present"
        } else if !paths.isEmpty {
            title = "Login-item related paths present (\(paths.count))"
        } else {
            title = "BTM / login-items inventory (no store detected)"
        }

        return [
            Finding(id: Self.id, title: title, severity: .info, category: .persist, resolution: .init(evidence: evidence, attackTechniques: ["T1547.015", "T1543.001"], remediation: [
                    "Review Login Items & Extensions and Background Items in System Settings",
                    "Unexpected BTM entries may indicate persistence; presence alone is not malicious",
                ], falsePositiveNotes: "BTM store existence is normal on modern macOS after apps register background tasks"), runtime: .init(confidence: hasBTM ? .medium : .low, dryRunSafe: true, opsecScore: 12, esfExpected: ["OPEN"])),
        ]
    }
}
