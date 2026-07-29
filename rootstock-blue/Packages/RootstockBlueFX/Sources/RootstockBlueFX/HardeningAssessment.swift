import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// Automated **hardening / defense assessment** - product feature, not docs-only.
///
/// Consumes IR posture (+ optional parser) events and emits structured
/// `harden.finding` envelopes with **operator-visible remediation** text.
/// Pure offline path is fixture-complete (security_posture.json + ALF + sysext + remote).
///
/// Does not become MDM or AV: assessment + guidance only; no policy push, no quarantine.
public enum HardeningAssessment {
    public struct Finding: Sendable, Equatable {
        public var control: String
        public var status: String // pass | fail | warn | unknown
        public var severity: String
        public var title: String
        public var detail: String
        public var remediation: String
        public var evidence: String

        public init(
            control: String,
            status: String,
            severity: String,
            title: String,
            detail: String,
            remediation: String,
            evidence: String = ""
        ) {
            self.control = control
            self.status = status
            self.severity = severity
            self.title = title
            self.detail = detail
            self.remediation = remediation
            self.evidence = evidence
        }
    }

    /// Assess from pre-collected posture/parser events (unit-testable pure path).
    public static func assess(events: [EventEnvelope]) -> [Finding] {
        [
            assessControlFindings(events),
            assessWaveFourFindings(events),
            assessWaveFiveFindings(events),
            assessWaveSixFindings(events),
            assessWaveSevenFindings(events),
            assessWaveEightToTwelveFindings(events),
            assessWaveThirteenToFourteenFindings(events),
            assessWaveFifteenFindings(events),
            assessWaveSixteenFindings(events),
        ].flatMap { $0 }
    }

    /// Offline assess from artifact tree: posture + wave-3/4/5/6/7/8 parsers.
    public static func assessOffline(source: ImageSource) throws -> [Finding] {
        let eventGroups = try [
            offlineFoundationEvents(source),
            offlineWaveFiveEvents(source),
            offlineWaveSixEvents(source),
            offlineWaveSevenEvents(source),
            offlineWaveEightToTwelveEvents(source),
            offlineWaveThirteenToFourteenEvents(source),
            offlineWaveFifteenEvents(source),
            offlineWaveSixteenEvents(source),
        ]
        return assess(events: eventGroups.flatMap { $0 })
    }

    /// Live assess using live IR posture probes (honest; no silent TCC bypass).
    public static func assessLive(runStatusProbes: Bool = true) -> [Finding] {
        let events = HostIRPosture.enumerateLive(runStatusProbes: runStatusProbes)
        return assess(events: events)
    }

    /// Convert findings to case-ready EventEnvelopes.
    public static func toEvents(_ findings: [Finding], mode: String) -> [EventEnvelope] {
        findings.map { f in
            EventEnvelope(
                identity: EventEnvelope.Identity(
                    kind: "harden.finding",
                    label: "HARDEN"
                ),
                capture: EventEnvelope.Capture(
                    source: .collect,
                    eventTime: Date(),
                    collectedAt: Date()
                ),
                payload: EventEnvelope.Payload(
                    entityRefs: [EntityID(kind: .host, value: "harden=\(f.control)")],
                    properties: [
                    "ir.mode": mode,
                    "harden.control": f.control,
                    "harden.status": f.status,
                    "harden.severity": f.severity,
                    "harden.title": f.title,
                    "harden.detail": f.detail,
                    "harden.remediation": f.remediation,
                    "harden.evidence": f.evidence,
                    FieldTaxonomy.eventType: "harden.finding",
                ],
                    confidence: f.status == "unknown" ? 0.5 : 0.92
                )
            )
        }
    }

    /// Write assessment events into a case package.
    @discardableResult
    public static func writeToCase(
        _ findings: [Finding],
        package: CasePackage,
        mode: String,
        actor: String = NSUserName()
    ) throws -> Int {
        let events = toEvents(findings, mode: mode)
        for event in events {
            try package.appendEventJSONL(event, stream: "es")
            try package.insertTimelineEvent(event)
        }
        try package.appendCustody(
            CustodyEvent(
                actor: actor,
                action: "harden_assess",
                detail: "Hardening assessment (\(mode)) findings=\(findings.count) fail=\(findings.filter { $0.status == "fail" }.count)"
            )
        )
        try package.updateHashes()
        return events.count
    }

    // MARK: - Control assessments

}
