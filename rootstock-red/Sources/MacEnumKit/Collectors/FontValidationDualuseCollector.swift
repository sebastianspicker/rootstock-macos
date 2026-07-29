import Foundation
import RootstockCore

/// Font validation / ATS dual-use surface (Wave-14).
/// Research basis: 2025–26 macOS Font validation dual-use tradecraft.
/// Safety and behavior: path inventory only; never installs malicious fonts or disables font validation.
public struct FontValidationDualuseCollector: Collector {
    public static let id = "collect.font_validation_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Font validation dual-use: path presence only - never installs malicious fonts or disables font validation"]
        var a: [String] = []
        for path in ["/System/Applications/Font Book.app",
            "/System/Library/Fonts",
            "/Library/Fonts"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/System/Library/Frameworks/ApplicationServices.framework/Frameworks/ATS.framework",
            "/usr/bin/atsutil",
            "/System/Library/PrivateFrameworks/FontServices.framework"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Fonts",
            NSHomeDirectory() + "/Library/Fonts Disabled",
            NSHomeDirectory() + "/Downloads"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.fontValidationDualuse = FontValidationDualuseState(
            fontToolPaths: a, atsSupportPaths: b, userFontPaths: c,
            fontSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
