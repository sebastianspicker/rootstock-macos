import Foundation
import RootstockCore

/// Path-to-impact: XPC / Privileged Helper Tools surface as abuse and persistence plane.
///
/// Research basis: PEASS helper listings, Empire OSX helper ideas, Objective-See XPC research themes.
/// Safety and behavior: typed vector with ATT&CK, SIP honesty, compound inject/helper signals,
/// not a rainbow dump of every helper filename.
public struct XPCHelperAbuseSurfaceVector: Check {
    public static let id = "rootstock.vector.xpc.helper_abuse_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let profile = riskProfile(for: state)
        guard profile.hasInitialSignal, profile.hasPaths, profile.shouldFire else { return [] }
        return [makeFinding(for: state, profile: profile)]
    }

    private struct XPCHelperRiskProfile {
        let helperCount: Int
        let extensionCount: Int
        let note: String?
        let writablePaths: [String]
        let injectCompound: Bool
        let scale: Bool
        let flaggedNote: Bool

        var hasInitialSignal: Bool { hasPaths || note != nil }
        var hasPaths: Bool { helperCount > 0 || extensionCount > 0 }

        var shouldFire: Bool {
            if !writablePaths.isEmpty || injectCompound { return true }
            return scale || flaggedNote
        }
    }

    private func riskProfile(for state: CollectedState) -> XPCHelperRiskProfile {
        let helpers = state.privilegedHelperTools
        let extensions = state.systemExtensionPaths
        let note = xpcCollectorNote(in: state)
        return XPCHelperRiskProfile(
            helperCount: helpers.count,
            extensionCount: extensions.count,
            note: note,
            writablePaths: writableHelperPaths(from: helpers, using: FileManager.default),
            injectCompound: hasInjectabilityCompound(in: state),
            scale: helpers.count + extensions.count >= 2,
            flaggedNote: isFlagged(note: note, state: state)
        )
    }

    private func xpcCollectorNote(in state: CollectedState) -> String? {
        state.collectorNotes["collect.xpc_helpers"]
            ?? state.collectorNotes.first(where: { $0.key.contains("xpc") })?.value
    }

    private func writableHelperPaths(from helpers: [String], using fileManager: FileManager) -> [String] {
        helpers.compactMap { helper in
            let path = helperPath(for: helper)
            return isWritable(path, using: fileManager) ? path : nil
        }
    }

    private func helperPath(for helper: String) -> String {
        helper.hasPrefix("/") ? helper : "/Library/PrivilegedHelperTools/\(helper)"
    }

    private func isWritable(_ path: String, using fileManager: FileManager) -> Bool {
        if fileManager.isWritableFile(atPath: path) { return true }
        let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
        return fileManager.isWritableFile(atPath: parent)
    }

    private func hasInjectabilityCompound(in state: CollectedState) -> Bool {
        state.injectabilityHits.contains {
            $0.disableLibraryValidation == true
                || $0.getTaskAllow == true
                || $0.hardenedRuntime == false
                || !$0.riskFlags.isEmpty
        }
    }

    private func isFlagged(note: String?, state: CollectedState) -> Bool {
        note?.localizedCaseInsensitiveContains("denied") == true
            || state.collectorNotes["privesc.xpc_risk"] != nil
    }

    private func makeFinding(for state: CollectedState, profile: XPCHelperRiskProfile) -> Finding {
        Finding(
            id: Self.id,
            title: title(for: profile),
            severity: severity(for: profile),
            category: .xpc,
            resolution: .init(
                evidence: evidence(for: state, profile: profile),
                attackTechniques: ["T1543.001", "T1543.004", "T1559", "T1068"],
                remediation: [
                    "Inventory PrivilegedHelperTools; remove unexpected vendor helpers",
                    "Ensure helpers are root-owned, signed, and not user-writable",
                    "Correlate with System Settings → Login Items / Background Items for residual services",
                    "OPSEC: filename listing is quiet; installing fake helpers is high-risk and lab-only",
                ],
                falsePositiveNotes: "Security and MDM products legitimately install helpers. Filenames-only inventory "
                    + "is not proof of vulnerable XPC interfaces - no private API reverse engineering performed."
            ),
            runtime: .init(
                confidence: .medium,
                dryRunSafe: true,
                opsecScore: profile.writablePaths.isEmpty ? 22 : 50,
                esfExpected: ["OPEN", "WRITE"]
            )
        )
    }

    private func title(for profile: XPCHelperRiskProfile) -> String {
        if !profile.writablePaths.isEmpty {
            return "XPC/helper abuse surface: user-writable privileged helpers (\(profile.writablePaths.count))"
        }
        if profile.injectCompound && profile.helperCount >= 1 {
            return "XPC/helper surface with injectability compound (\(profile.helperCount) helpers)"
        }
        return "XPC/privileged-helper attack surface (\(profile.helperCount + profile.extensionCount) paths)"
    }

    private func severity(for profile: XPCHelperRiskProfile) -> Severity {
        if !profile.writablePaths.isEmpty { return .high }
        return profile.injectCompound && profile.helperCount >= 1 ? .medium : .low
    }

    private func evidence(for state: CollectedState, profile: XPCHelperRiskProfile) -> [Evidence] {
        var evidence = [
            Evidence(
                type: "summary",
                detail: "privilegedHelpers=\(profile.helperCount) systemExtensions=\(profile.extensionCount) "
                    + "writableHelpers=\(profile.writablePaths.count) injectCompound=\(profile.injectCompound)"
            ),
        ]
        if let note = profile.note {
            evidence.append(Evidence(type: "xpc_collector", detail: note))
        }
        evidence.append(contentsOf: helperEvidence(from: state.privilegedHelperTools))
        evidence.append(contentsOf: extensionEvidence(from: state.systemExtensionPaths))
        if profile.injectCompound {
            evidence.append(
                Evidence(
                    type: "compound_inject",
                    detail: "injectability risk flags present - helper install + weak HR is higher impact"
                )
            )
        }
        if state.protections?.sipEnabled == true {
            evidence.append(
                Evidence(
                    type: "sip_honesty",
                    detail: "SIP on - system helper install still needs root; abuse is usually existing weak helpers"
                )
            )
        }
        return evidence
    }

    private func helperEvidence(from helpers: [String]) -> [Evidence] {
        helpers.prefix(25).map { helper in
            Evidence(
                type: "xpc_helper",
                path: helperPath(for: helper),
                detail: "name=\(helper) (filename/path inventory; no binary reverse)"
            )
        }
    }

    private func extensionEvidence(from extensions: [String]) -> [Evidence] {
        extensions.prefix(15).map { Evidence(type: "system_extension", path: $0, detail: "sygext path present") }
    }
}
