import Foundation
import RootstockCore

/// Path-to-impact: browser session/cookie/login DB metadata as a credential pivot surface.
///
/// Reads only path presence, size, and modification time. It never reads
/// database row contents.
public struct BrowserSessionArtifactPivotVector: Check {
    public static let id = "rootstock.vector.browser.session_artifact_pivot"
    public static let cost: CollectorCost = .low

    /// High-value artifact kinds (session / auth adjacent).
    private static let highValueKinds: Set<String> = [
        "cookies", "cookie", "login_data", "logins", "web_data",
        "keychain", "session", "sessions", "preferences",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let present = state.browserMeta.filter(\.exists)
        guard !present.isEmpty else { return [] }

        let highValue = present.filter { entry in
            let kind = entry.kind.lowercased()
            return Self.highValueKinds.contains(where: { kind.contains($0) })
                || kind.contains("cookie")
                || kind.contains("login")
        }
        let focus = highValue.isEmpty ? present : highValue
        guard !focus.isEmpty else { return [] }

        let fda = state.tcc?.fullDiskAccessLikely == true
        let presentation = Self.presentation(
            presentCount: present.count,
            highValueCount: highValue.count,
            fda: fda
        )
        return [Self.finding(
            evidence: evidence(for: state),
            title: presentation.title,
            severity: presentation.severity,
            tccDomains: fda ? ["FullDiskAccess"] : []
        )]
    }

    private struct Presentation {
        let title: String
        let severity: Severity
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let present = state.browserMeta.filter(\.exists)
        let highValue = present.filter { entry in
            let kind = entry.kind.lowercased()
            return Self.highValueKinds.contains(where: { kind.contains($0) })
                || kind.contains("cookie")
                || kind.contains("login")
        }
        let focus = highValue.isEmpty ? present : highValue
        var evidence = [Evidence(
            type: "summary",
            detail: "browserMetaPresent=\(present.count) highValueKinds=\(highValue.count) (metadata only - no cookie/password row contents)"
        )]
        for entry in focus.prefix(30) {
            evidence.append(Evidence(
                type: "browser_artifact",
                path: entry.path,
                detail: Self.artifactDetail(for: entry)
            ))
        }
        evidence.append(contentsOf: compoundEvidence(for: state))
        return evidence
    }

    private func compoundEvidence(for state: CollectedState) -> [Evidence] {
        var evidence: [Evidence] = []
        if state.tcc?.fullDiskAccessLikely == true {
            evidence.append(Evidence(
                type: "compound_fda",
                detail: "FDA likely - browser DB paths may be readable beyond sandbox defaults"
            ))
        }
        let sshOrCloud = state.credPaths.filter {
            $0.exists && ["ssh", "aws", "gcp", "azure"].contains($0.kind)
        }
        if !sshOrCloud.isEmpty {
            evidence.append(Evidence(
                type: "compound_creds",
                detail: "cloud/ssh cred paths also present (\(sshOrCloud.count)) - multi-artifact pivot"
            ))
        }
        return evidence
    }

    private static func artifactDetail(for entry: BrowserMetaEntry) -> String {
        var detail = "browser=\(entry.browser) kind=\(entry.kind)"
        if let size = entry.sizeBytes { detail += " sizeBytes=\(size)" }
        if let modified = entry.modifiedAt {
            detail += " mtime=\(ISO8601DateFormatter().string(from: modified))"
        }
        return detail
    }

    private static func presentation(presentCount: Int, highValueCount: Int, fda: Bool) -> Presentation {
        if highValueCount > 0 && fda {
            return .init(
                title: "Browser session pivot: high-value DBs present with FDA-likely context (\(highValueCount))",
                severity: .medium
            )
        }
        if highValueCount > 0 {
            return .init(
                title: "Browser session artifact pivot surface (\(highValueCount) high-value DBs)",
                severity: .medium
            )
        }
        return .init(
            title: "Browser profile artifact surface (\(presentCount) paths present)",
            severity: .low
        )
    }

    private static func finding(
        evidence: [Evidence],
        title: String,
        severity: Severity,
        tccDomains: [String]
    ) -> Finding {
        Finding(id: Self.id, title: title, severity: severity, category: .auth, resolution: .init(evidence: evidence, attackTechniques: ["T1539", "T1555.003", "T1005", "T1083"], remediation: [
                "Lock browser profiles; prefer OS keychain-backed passwords with device auth",
                "Clear stale session cookies on shared or high-risk hosts",
                "Do not grant FDA to untrusted tools that can read browser DB paths",
                "OPSEC: Rootstock Red assess never dumps cookies/passwords - path metadata only",
            ], falsePositiveNotes: "Browser cookie/login DB files exist on nearly all user hosts; finding is path-to-impact surface, not proof of theft. App-Bound / sandboxing may still block access without FDA."), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 24, tccDomains: tccDomains, esfExpected: ["OPEN"]))
    }
}
