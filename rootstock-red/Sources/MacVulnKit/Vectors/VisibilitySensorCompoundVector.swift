import Foundation
import RootstockCore

/// Wave-10 compound depth: thin TCC/ESF visibility × missing sensors.
///
/// Research basis: eslogger / Unified Logging / TCC.db path visibility literature.
/// Safety and behavior: thin/partial visibility compounded with empty ESF clients or absent products; never dumps TCC.db.
public struct VisibilitySensorCompoundVector: Check {
    public static let id = "rootstock.vector.esf.visibility_sensor_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard Self.hasVisibilitySurface(state), Self.hasVisibilityGap(state), Self.hasSensorGap(state) else { return [] }
        return [Self.finding(for: state, evidence: evidence(for: state))]
    }


    private static func hasVisibilitySurface(_ state: CollectedState) -> Bool {
        let depth = state.tccEsfVisibilityDepth
        return depth?.visibilitySurfacePresent == true || (depth?.tccDbPathHits.count ?? 0) > 0
            || (depth?.visibilityToolPaths.count ?? 0) > 0 || (depth?.privacyPrefPaths.count ?? 0) > 0
    }

    private static func hasVisibilityGap(_ state: CollectedState) -> Bool {
        let depth = state.tccEsfVisibilityDepth
        return depth?.visibilityDepth == "thin" || depth?.visibilityDepth == "partial"
            || (depth?.visibilityToolPaths.count ?? 0) < 2
    }

    private static func hasSensorGap(_ state: CollectedState) -> Bool {
        state.esf?.clientPaths.isEmpty == true
            || (state.esf == nil && state.collectorNotes["collect.esf_endpoint_security"] != nil)
            || state.securityProducts.filter(\.present).isEmpty
    }

    private static func remoteAccess(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
    }

    private func evidence(for state: CollectedState) -> [Evidence] {
        let depth = state.tccEsfVisibilityDepth, tcc = depth?.tccDbPathHits.count ?? 0, tools = depth?.visibilityToolPaths.count ?? 0, prefs = depth?.privacyPrefPaths.count ?? 0
        let label = depth?.visibilityDepth ?? "unknown", esfEmpty = state.esf?.clientPaths.isEmpty == true || (state.esf == nil && state.collectorNotes["collect.esf_endpoint_security"] != nil), productsAbsent = state.securityProducts.filter(\.present).isEmpty
        let fda = state.tcc?.fullDiskAccessLikely == true, remote = Self.remoteAccess(state)
        var evidence: [Evidence] = [Evidence(type: "visibility_sensor_compound_summary", detail: "depth=\(label) tccPaths=\(tcc) tools=\(tools) prefs=\(prefs) " + "esfEmpty=\(esfEmpty) productsAbsent=\(productsAbsent) " + "fda=\(fda) remote=\(remote)")]
        if let depth {
            for path in (depth.tccDbPathHits + depth.visibilityToolPaths).prefix(10) { evidence.append(Evidence(type: "visibility_path", path: path, detail: "visibility component (meta only)")) }
            for note in depth.notes.prefix(4) { evidence.append(Evidence(type: "visibility_note", detail: note)) }
        }
        evidence.append(Evidence(type: "compound_sensor_gap", detail: "sensor gap co-presence: esfClientsEmpty=\(esfEmpty) securityProductsAbsent=\(productsAbsent)"))
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps TCC.db rows, never live-subscribes Endpoint Security without ROE, " + "never disables logging or unloads sensors."))
        return evidence
    }

    private static func finding(for state: CollectedState, evidence: [Evidence]) -> Finding {
        let depth = state.tccEsfVisibilityDepth, label = depth?.visibilityDepth ?? "unknown", thin = label == "thin" || label == "partial", esfEmpty = state.esf?.clientPaths.isEmpty == true || (state.esf == nil && state.collectorNotes["collect.esf_endpoint_security"] != nil)
        let sensorGap = hasSensorGap(state), remote = remoteAccess(state)
        let severity: Severity = thin && esfEmpty && remote ? .high : (thin && sensorGap ? .medium : .low)
        return Finding(id: Self.id, title: thin ? "TCC/ESF visibility depth \(label) compounds with sensor gap" : "Thin visibility tooling compounds with missing ESF/security products", severity: severity, category: .misconfig, resolution: .init(evidence: evidence, attackTechniques: ["T1562.001", "T1083", "T1005"], remediation: ["Deploy Endpoint Security clients and ensure TCC/FDA grants for security products", "Enable eslogger / Unified Logging pipelines under ROE for purple validation", "Treat unreadable TCC paths as expected without FDA - do not dump rows", "OPSEC: Rootstock Red does not dump TCC.db or unload sensors"], falsePositiveNotes: "TCC.db is often unreadable without FDA. Prefer thin/partial depth + empty ESF clients " + "or absent security products over single path misses on hardened hosts."), runtime: .init(confidence: .medium, dryRunSafe: true, opsecScore: 24, esfExpected: ["OPEN", "READ"]))
    }
}
