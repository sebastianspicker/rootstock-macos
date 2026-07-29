import Foundation
import RootstockCore

/// CVE / patch-debt suggester - exploitability context, not an exploit pack.
///
/// Research basis: PEASS version checks; compliance "days behind" scanners.
/// Safety and behavior: typed PatchDebtState; major-version lag + SUS presence; low confidence by
/// default; never downloads or runs exploits; language is suggester-only.
public struct CVEPatchDebtSuggesterVector: Check {
    public static let id = "rootstock.vector.cve.patch_debt_suggester"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws
        -> [Finding]
    {
        guard let assessment = Self.assessment(for: state),
            Self.shouldFire(assessment, state: state)
        else { return [] }
        return [Self.finding(for: state, assessment: assessment)]
    }

    private struct Assessment {
        let hostVersion: String?
        let effectiveLag: Int
    }

    private static func assessment(for state: CollectedState) -> Assessment? {
        let debt = state.patchDebt
        let hostVersion = debt?.osVersion ?? state.host?.osVersion
        guard hostVersion != nil || debt != nil else { return nil }
        let reportedLag = debt?.majorVersionLag ?? 0
        let parsedMajor = hostVersion?.split(separator: ".").first.flatMap { Int($0) }
        let effectiveLag =
            reportedLag > 0
            ? reportedLag
            : parsedMajor.map { max(0, PatchDebtCollectorKnownCurrent.major - $0) } ?? 0
        return Assessment(hostVersion: hostVersion, effectiveLag: effectiveLag)
    }

    private static func shouldFire(_ assessment: Assessment, state: CollectedState) -> Bool {
        let forceNote = state.collectorNotes["cve.patch_debt"] != nil
        let hygieneGap =
            state.patchDebt != nil
            && state.patchDebt?.softwareUpdatePlistPresent == false
            && (state.network?.remoteLoginSSH == true || state.identity?.adBound == true)
        return assessment.effectiveLag >= 1 || forceNote || hygieneGap
    }

    private static func finding(for state: CollectedState, assessment: Assessment) -> Finding {
        let presentation = Self.presentation(for: assessment.effectiveLag)
        return Finding(id: Self.id, title: presentation.title, severity: presentation.severity, category: .cve, resolution: .init(evidence: evidence(for: state, assessment: assessment), attackTechniques: ["T1082", "T1203", "T1068"], remediation: [
                "Apply latest security updates via MDM / Software Update for this hardware class",
                "Map ProductBuildVersion to Apple security content before claiming exploitability",
                "Prioritize internet-facing and remotely accessible hosts first",
                "OPSEC: assess does not fetch exploit PoCs or weaponize CVEs",
            ], falsePositiveNotes: "Known-current major baseline is product-maintained and may lag Apple's newest release. "
                + "Managed freeze windows can intentionally lag majors."), runtime: .init(confidence: .low, dryRunSafe: true, opsecScore: 8, esfExpected: ["OPEN"], osRange: assessment.hostVersion))
    }

    private static func evidence(for state: CollectedState, assessment: Assessment) -> [Evidence] {
        let debt = state.patchDebt
        var evidence = [
            Evidence(
                type: "os",
                detail: "osVersion=\(assessment.hostVersion ?? "unknown") "
                    + "build=\(debt?.osBuild ?? state.host?.osBuild ?? "unknown") majorVersionLag=\(assessment.effectiveLag)"
            ),
            Evidence(
                type: "suggester_honesty",
                detail: "This finding is patch-debt context only. It does not prove a specific CVE "
                    + "is exploitable on this host and does not include exploit code."),
        ]
        appendDebtEvidence(debt, to: &evidence)
        if remoteOrIdentity(state) {
            evidence.append(
                Evidence(
                    type: "compound",
                    detail: "Remote and/or enterprise identity increases priority of patch hygiene")
            )
        }
        appendLagEvidence(assessment.effectiveLag, to: &evidence)
        return evidence
    }

    private static func appendDebtEvidence(_ debt: PatchDebtState?, to evidence: inout [Evidence]) {
        guard let debt else { return }
        evidence.append(
            Evidence(
                type: "sus",
                detail:
                    "softwareUpdatePlistPresent=\(debt.softwareUpdatePlistPresent.rootstockDescribe)"
            ))
        evidence += debt.lastUpdateHints.prefix(8).map { Evidence(type: "update_hint", detail: $0) }
        evidence += debt.notes.prefix(10).map { Evidence(type: "note", detail: $0) }
    }

    private static func appendLagEvidence(_ lag: Int, to evidence: inout [Evidence]) {
        let detail: String?
        if lag >= 2 {
            detail =
                "Multi-major lag may increase exposure to historical local-privilege and sandbox escape classes already patched on current majors - verify with vendor advisories for this exact build."
        } else if lag == 1 {
            detail =
                "One major behind baseline: prioritize security updates; map build to Apple security updates before assuming exploitability."
        } else {
            detail = nil
        }
        if let detail { evidence.append(Evidence(type: "class_suggestion", detail: detail)) }
    }

    private static func presentation(for lag: Int) -> (severity: Severity, title: String) {
        if lag >= 2 {
            return (.medium, "Patch-debt suggester: OS major lag \(lag) (CVE class context only)")
        }
        if lag == 1 { return (.low, "Patch-debt suggester: OS one major behind baseline") }
        return (.low, "Patch-debt suggester: update hygiene gap (SUS prefs absent)")
    }

    private static func remoteOrIdentity(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
            || state.identity?.adBound == true
            || state.identity?.platformSSO == true
    }

}

/// Mirrors `PatchDebtCollector.knownCurrentMajor` for evaluate() without importing MacEnumKit cycles.
enum PatchDebtCollectorKnownCurrent {
    static let major = 15
}
