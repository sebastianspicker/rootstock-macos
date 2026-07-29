import Foundation
import RootstockCore

/// Wave-11 compound: browser extensions × FDA / remote collection impact.
public struct BrowserExtensionCollectionCompoundVector: Check {
    public static let id = "rootstock.vector.persist.browser_extension_collection_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let be = state.browserExtensionDualUse
        let chromium = be?.chromiumExtensionPaths.count ?? 0
        let safari = be?.safariExtensionPaths.count ?? 0
        guard chromium + safari >= 1 else { return [] }

        let fda = state.tcc?.fullDiskAccessLikely == true
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let stealerAdj = state.infoStealerPathPlane?.collectionSurfacePresent == true
        guard fda || remote || stealerAdj || (chromium >= 1 && safari >= 1) else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "browser_extension_collection_compound",
                detail:
                    "chromium=\(chromium) safari=\(safari) fda=\(fda) remote=\(remote) stealerAdj=\(stealerAdj)"
            ),
        ]
        if let be {
            for path in (be.chromiumExtensionPaths + be.safariExtensionPaths).prefix(8) {
                evidence.append(Evidence(type: "extension_compound_path", path: path, detail: "extension×collection"))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail: "Never dumps extension storage, cookies, or passwords."
            )
        )

        let severity: Severity
        if fda && remote && chromium + safari >= 2 {
            severity = .high
        } else if fda || (remote && stealerAdj) {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(id: Self.id, title: fda
                    ? "Browser extension × collection-impact compound under FDA"
                    : "Browser extension × multi-browser collection compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1176", "T1555.003", "T1005"], remediation: [
                    "Treat extension roots + FDA as stealer-adjacent collection surface",
                    "Enforce extension allowlists; audit Secure Preferences changes",
                    "OPSEC: no secret export from browser profiles",
                ], falsePositiveNotes: "Multi-browser enterprises are common; prioritize FDA/remote amplifiers."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "READ"])),
        ]
    }
}
