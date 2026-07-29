import Foundation
import RootstockCore

/// Gatekeeper assessment / syspolicyd history depth (Wave-13).
///
/// Research basis: public 2025–26 macOS Gatekeeper assessment history tradecraft research.
/// Safety and behavior: typed path inventory only; never clears Gatekeeper assessments or disables syspolicyd.
public struct GatekeeperAssessmentHistoryCollector: Collector {
    public static let id = "collect.gatekeeper_assessment_history"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Gatekeeper assessment history: path presence only - never clears Gatekeeper assessments or disables syspolicyd",
        ]
        var a: [String] = []
        for path in ["/usr/libexec/syspolicyd",
            "/System/Library/LaunchDaemons/com.apple.syspolicyd.plist",
            "/System/Library/PrivateFrameworks/SystemPolicy.framework"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/var/db/SystemPolicyConfiguration",
            "/Library/Preferences/com.apple.security.plist",
            NSHomeDirectory() + "/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/usr/sbin/spctl",
            "/usr/bin/codesign",
            "/usr/sbin/syspolicy"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.gatekeeperAssessmentHistory = GatekeeperAssessmentHistoryState(
            syspolicydPaths: a,
            assessmentDbPaths: b,
            spctlToolPaths: c,
            assessmentSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
