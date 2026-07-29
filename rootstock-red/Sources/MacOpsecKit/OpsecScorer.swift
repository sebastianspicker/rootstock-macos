import Foundation
import RootstockCore

/// Computes 0–100 OPSEC noise scores (higher = noisier).
public struct OpsecScorer: Sendable {
    public var weights: OpsecWeights

    public init(weights: OpsecWeights = .default) {
        self.weights = weights
    }

    public func score(_ signals: OpsecSignals) -> Int {
        var total = 0
        total += min(signals.processSpawns, 5) * weights.processSpawn
        total += min(signals.sensitiveFileOpens, 5) * weights.sensitiveFileOpen
        total += min(signals.tccDomains.count, 4) * weights.tccDomainTouch
        if signals.networkEgress { total += weights.networkEgress }
        if signals.userVisible { total += weights.userVisible }
        // Distinct ESF classes (exclude synthetic USER_PROMPT which is covered by userVisible).
        let esfCount = Set(
            signals.esfEventClasses.filter { !$0.uppercased().contains("USER_PROMPT") }
        ).count
        total += min(esfCount, 6) * weights.esfEventClass
        total += min(signals.sensitivePathReads, 5) * weights.sensitivePathRead
        if signals.appleEvents { total += weights.appleEvents }
        return min(100, total)
    }

    /// Human-readable score breakdown for evidence / debugging.
    public func breakdown(_ signals: OpsecSignals) -> String {
        let esf = signals.esfEventClasses.isEmpty
            ? "none"
            : signals.esfEventClasses.joined(separator: ",")
        let tcc = signals.tccDomains.isEmpty
            ? "none"
            : signals.tccDomains.joined(separator: ",")
        return [
            "score=\(score(signals))",
            "esf=[\(esf)]",
            "tcc=[\(tcc)]",
            "pathOpens=\(signals.sensitiveFileOpens)",
            "sensitiveReads=\(signals.sensitivePathReads)",
            "net=\(signals.networkEgress)",
            "userVisible=\(signals.userVisible)",
            "appleEvents=\(signals.appleEvents)",
            "spawns=\(signals.processSpawns)",
        ].joined(separator: " ")
    }

    /// Attach score (always) and enrich ESF expectations from category when empty.
    public func annotate(_ finding: Finding) -> Finding {
        var copy = finding

        if copy.esfExpected.isEmpty {
            copy.esfExpected = OpsecESFCatalog.defaultShortClasses(for: copy.category)
        }
        let signals = signals(for: copy)

        let scoreValue = score(signals)
        copy.opsecScore = scoreValue

        // Schema-compatible optional note (Evidence.type = "opsec").
        if !copy.evidence.contains(where: { $0.type == "opsec" }) {
            copy.evidence.append(
                Evidence(
                    type: "opsec",
                    detail: breakdown(signals)
                )
            )
        }

        return copy
    }

    private func signals(for finding: Finding) -> OpsecSignals {
        let paths = finding.evidence.compactMap(\.path)
        let classes = finding.esfExpected.map { $0.uppercased() }
        return OpsecSignals(
            processSpawns: classes.contains(where: isProcessEvent) ? 1 : 0,
            sensitiveFileOpens: paths.count, tccDomains: finding.tccDomains,
            networkEgress: finding.category == .network || classes.contains(where: isNetworkEvent),
            userVisible: classes.contains { $0.contains("USER_PROMPT") },
            esfEventClasses: OpsecESFCatalog.notifyEventNames(from: finding.esfExpected),
            sensitivePathReads: paths.filter(OpsecESFCatalog.isSensitivePath).count,
            appleEvents: finding.tccDomains.contains { $0.lowercased().contains("appleevent") || $0.lowercased().contains("automation") }
        )
    }

    private func isProcessEvent(_ event: String) -> Bool { event == "EXEC" || event == "FORK" || event.contains("NOTIFY_EXEC") || event.contains("NOTIFY_FORK") }
    private func isNetworkEvent(_ event: String) -> Bool { event.contains("CONNECT") || event.contains("NETWORK") || event == "LOOKUP" }

    public func annotateAll(_ findings: [Finding]) -> [Finding] {
        findings.map { annotate($0) }
    }
}
