import Foundation
import RootstockCore

/// Cron / at job dual-use residual depth (Wave-14).
/// Research basis: 2025–26 macOS Cron/at job depth tradecraft.
/// Safety and behavior: path inventory only; never installs cron or at jobs outside the lab root.
public struct CronAtJobDepthCollector: Collector {
    public static let id = "collect.cron_at_job_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Cron/at job depth: path presence only - never installs cron or at jobs outside the lab root"]
        var a: [String] = []
        for path in ["/usr/sbin/cron",
            "/usr/bin/crontab",
            "/System/Library/LaunchDaemons/com.vix.cron.plist"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/var/at/tabs",
            "/private/var/at/tabs",
            NSHomeDirectory() + "/Library/LaunchAgents"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/usr/bin/at",
            "/usr/bin/atq",
            "/var/at/jobs",
            "/private/var/at/jobs"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.cronAtJobDepth = CronAtJobDepthState(
            cronBinaryPaths: a, crontabPaths: b, atJobPaths: c,
            cronAtSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
