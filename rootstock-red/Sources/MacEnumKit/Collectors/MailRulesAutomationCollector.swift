import Foundation
import RootstockCore

/// Mail rules / Apple Mail automation persistence (Wave-12).
///
/// Research basis: public 2025–26 macOS Mail rules automation tradecraft research.
/// Safety and behavior: typed path inventory only; never reads Mail contents or modifies user Mail rules.
public struct MailRulesAutomationCollector: Collector {
    public static let id = "collect.mail_rules_automation"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Mail rules automation: path presence only - never reads Mail contents or modifies user Mail rules",
        ]

        var a: [String] = []
        for path in ["/System/Applications/Mail.app",
            "/Applications/Mail.app",
            NSHomeDirectory() + "/Library/Mail"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Mail/V10/MailData/SyncedRules.plist",
            NSHomeDirectory() + "/Library/Mail/V9/MailData/SyncedRules.plist",
            NSHomeDirectory() + "/Library/Mail/V8/MailData/SyncedRules.plist",
            NSHomeDirectory() + "/Library/Containers/com.apple.mail/Data/Library/Mail"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/usr/bin/osascript",
            "/System/Library/Frameworks/MailKit.framework",
            NSHomeDirectory() + "/Library/Application Scripts/com.apple.mail"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }

        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2

        var state = CollectedState()
        state.mailRulesAutomation = MailRulesAutomationState(
            mailAppPaths: a,
            rulesPlistPaths: b,
            scriptingAdjacentPaths: c,
            rulesSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
