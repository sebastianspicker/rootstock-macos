import Foundation
import RootstockCore

/// Path-to-impact: XPC / privileged-helper *client validation* trust surface.
///
/// Research basis: Objective-See XPC research; PEASS helper listings; CDHash+NIB helper themes.
/// Safety and behavior: compound helper inventory with inject/codesign weakness and SIP honesty;
/// distinct from filename-only abuse surface - emphasizes trust-validation gap narrative.
public struct XPCClientValidationSurfaceVector: Check {
    public static let id = "rootstock.vector.xpc.client_validation_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let profile = riskProfile(for: state)
        guard profile.hasPaths, profile.shouldFire else { return [] }
        return [makeFinding(for: state, profile: profile)]
    }

    private struct XPCValidationRiskProfile {
        let helperCount: Int
        let extensionCount: Int
        let injectWeak: Bool
        let unsignedish: Bool
        let riskNote: Bool
        let noEDR: Bool
        let scale: Bool

        var hasPaths: Bool { helperCount > 0 || extensionCount > 0 }

        var shouldFire: Bool {
            if injectWeak || unsignedish || riskNote { return true }
            if helperCount >= 3 { return true }
            return scale && noEDR
        }
    }

    private func riskProfile(for state: CollectedState) -> XPCValidationRiskProfile {
        let helperCount = state.privilegedHelperTools.count
        let extensionCount = state.systemExtensionPaths.count
        return XPCValidationRiskProfile(
            helperCount: helperCount,
            extensionCount: extensionCount,
            injectWeak: hasInjectabilityWeakness(in: state),
            unsignedish: hasWeakCodeSignSample(in: state),
            riskNote: hasRiskNote(in: state),
            noEDR: !state.securityProducts.contains(where: \.present),
            scale: helperCount + extensionCount >= 2
        )
    }

    private func hasInjectabilityWeakness(in state: CollectedState) -> Bool {
        state.injectabilityHits.contains { hit in
            hit.disableLibraryValidation == true
                || hit.getTaskAllow == true
                || hit.hardenedRuntime == false
                || hit.riskFlags.contains("disable-library-validation")
        }
    }

    private func hasWeakCodeSignSample(in state: CollectedState) -> Bool {
        state.codesignSamples.contains { $0.signed == false || $0.hardenedRuntime == false }
    }

    private func hasRiskNote(in state: CollectedState) -> Bool {
        state.collectorNotes["privesc.xpc_risk"] != nil
            || state.collectorNotes["xpc.client_validation"] != nil
    }

    private func makeFinding(for state: CollectedState, profile: XPCValidationRiskProfile) -> Finding {
        Finding(
            id: Self.id,
            title: title(for: profile),
            severity: severity(for: profile),
            category: .xpc,
            resolution: .init(
                evidence: evidence(for: state, profile: profile),
                attackTechniques: ["T1559", "T1543.001", "T1543.004", "T1068"],
                remediation: [
                    "Inventory and remove unexpected Privileged Helper Tools",
                    "Prefer helpers that validate client audit token + code signature (Team ID)",
                    "Correlate with Login Items / BTM for residual helper services",
                    "OPSEC: listing helpers is quiet; installing fake helpers is lab-only high risk",
                ],
                falsePositiveNotes: "Security/MDM products legitimately install helpers. Filename inventory is not proof "
                    + "of a vulnerable XPC interface."
            ),
            runtime: .init(
                confidence: .medium,
                dryRunSafe: true,
                opsecScore: profile.injectWeak ? 48 : 28,
                esfExpected: ["OPEN"]
            )
        )
    }

    private func title(for profile: XPCValidationRiskProfile) -> String {
        if profile.injectWeak && profile.helperCount > 0 {
            return "XPC client-validation surface: helpers with injectability compound"
        }
        if profile.helperCount >= 3 {
            return "XPC client-validation surface: large helper inventory (\(profile.helperCount))"
        }
        return "XPC helper trust surface (\(profile.helperCount + profile.extensionCount) paths)"
    }

    private func severity(for profile: XPCValidationRiskProfile) -> Severity {
        if profile.injectWeak && profile.helperCount > 0 { return .high }
        return profile.helperCount >= 3 ? .medium : .low
    }

    private func evidence(for state: CollectedState, profile: XPCValidationRiskProfile) -> [Evidence] {
        var evidence = baseEvidence(for: profile)
        evidence.append(contentsOf: helperEvidence(from: state.privilegedHelperTools))
        evidence.append(contentsOf: extensionEvidence(from: state.systemExtensionPaths))
        if profile.injectWeak {
            evidence.append(contentsOf: injectabilityEvidence(from: state))
        }
        if state.protections?.sipEnabled == true {
            evidence.append(sipHonestyEvidence())
        }
        return evidence
    }

    private func baseEvidence(for profile: XPCValidationRiskProfile) -> [Evidence] {
        [
            Evidence(
                type: "summary",
                detail: "helpers=\(profile.helperCount) sysext=\(profile.extensionCount) "
                    + "injectWeak=\(profile.injectWeak) unsignedish=\(profile.unsignedish) noEDR=\(profile.noEDR)"
            ),
            Evidence(
                type: "trust_narrative",
                detail: "Public XPC abuse classes often involve helpers that under-validate client "
                    + "code signature / team ID / audit token. Assess does not reverse private "
                    + "XPC protocols - this finding flags surface for manual authorized review."
            ),
        ]
    }

    private func helperEvidence(from helpers: [String]) -> [Evidence] {
        helpers.prefix(20).map { helper in
            let path = helper.hasPrefix("/") ? helper : "/Library/PrivilegedHelperTools/\(helper)"
            return Evidence(type: "helper", path: path, detail: "privileged helper inventory entry (no binary reverse)")
        }
    }

    private func extensionEvidence(from extensions: [String]) -> [Evidence] {
        extensions.prefix(10).map { Evidence(type: "system_extension", path: $0, detail: "sygext path") }
    }

    private func injectabilityEvidence(from state: CollectedState) -> [Evidence] {
        state.injectabilityHits.filter {
            $0.disableLibraryValidation == true || $0.getTaskAllow == true || $0.hardenedRuntime == false
        }.prefix(8).map {
            Evidence(type: "inject_compound", path: $0.path, detail: "flags=\($0.riskFlags.joined(separator: ","))")
        }
    }

    private func sipHonestyEvidence() -> Evidence {
        Evidence(
            type: "sip_honesty",
            detail: "SIP on - installing new system helpers still needs root; focus on existing helpers"
        )
    }
}
