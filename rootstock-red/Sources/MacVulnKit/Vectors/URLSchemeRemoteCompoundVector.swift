import Foundation
import RootstockCore

/// Wave-11 compound: URL scheme handlers × remote access path-to-impact.
public struct URLSchemeRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.delivery.url_scheme_remote_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let uh = state.urlSchemeHandler
        let ls = uh?.launchServicesPaths.count ?? 0
        let openers = uh?.openerBinaryPaths.count ?? 0
        guard ls >= 1, openers >= 1 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        guard remote || (uh?.handlerSurfacePresent == true && openers >= 2) else { return [] }

        let gkOff = state.protections?.gatekeeperEnabled == false
        let amplified = remote || gkOff

        var evidence: [Evidence] = [
            Evidence(
                type: "url_scheme_remote_compound",
                detail: "ls=\(ls) openers=\(openers) remote=\(remote) gkOff=\(gkOff) amplified=\(amplified)"
            ),
        ]
        if let uh {
            for path in (uh.launchServicesPaths + uh.openerBinaryPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "handler×opener"))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail: "Never registers URL schemes or rewrites LaunchServices handlers."
            )
        )

        let severity: Severity = amplified && remote ? .high : (amplified ? .medium : .low)
        return [
            Finding(id: Self.id, title: remote
                    ? "URL scheme handler × remote access compound"
                    : "URL scheme handler × opener compound", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1204", "T1021", "T1546"], remediation: [
                    "Prioritize hosts where custom handlers co-locate with SSH/ARD",
                    "Audit non-default LS handlers after remote sessions",
                    "OPSEC: path-to-impact only - not an auto-exploit chain",
                ], falsePositiveNotes: "Remote + stock open/osascript is common; rank unexpected third-party handlers first."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC"])),
        ]
    }
}
