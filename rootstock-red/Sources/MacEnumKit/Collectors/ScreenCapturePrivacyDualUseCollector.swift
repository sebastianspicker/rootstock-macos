import Foundation
import RootstockCore

/// ScreenCapture / screenshot privacy dual-use depth (Wave-13).
///
/// Research basis: public 2025–26 macOS ScreenCapture privacy dual-use tradecraft research.
/// Safety and behavior: typed path inventory only; never captures screens or dumps Screen Recording TCC rows.
public struct ScreenCapturePrivacyDualUseCollector: Collector {
    public static let id = "collect.screencapture_privacy_dualuse"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "ScreenCapture privacy dual-use: path presence only - never captures screens or dumps Screen Recording TCC rows",
        ]
        var a: [String] = []
        for path in ["/usr/sbin/screencapture",
            "/System/Library/CoreServices/Screenshot.app",
            "/System/Applications/Utilities/Screenshot.app"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/System/Library/Frameworks/ScreenCaptureKit.framework",
            "/System/Library/PrivateFrameworks/SkyLight.framework",
            "/System/Library/Frameworks/CoreGraphics.framework"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Desktop",
            NSHomeDirectory() + "/Pictures/Screenshots",
            NSHomeDirectory() + "/Library/ScreenRecordings"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.screenCapturePrivacyDualUse = ScreenCapturePrivacyDualUseState(
            screencaptureToolPaths: a,
            screenCaptureKitPaths: b,
            screenshotDropHints: c,
            captureSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
