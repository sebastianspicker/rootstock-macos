import Foundation
import RootstockCore

/// FaceTime / camera pipeline dual-use surface (Wave-16).
/// Safety and behavior: path inventory only; never activates camera/mic or dumps FaceTime call history contents.
public struct FacetimeCameraSurfaceCollector: Collector {
    public static let id = "collect.facetime_camera_surface"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["FaceTime camera dual-use: path presence only - never activates camera/mic or dumps FaceTime call history contents"]
        var a: [String] = []
        for path in ["/System/Applications/FaceTime.app",
            "/System/Library/PrivateFrameworks/FaceTime.framework",
            "/System/Library/Frameworks/AVFoundation.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/usr/libexec/avconferenced",
            "/System/Library/PrivateFrameworks/AVConference.framework"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.FaceTime.plist",
            NSHomeDirectory() + "/Library/Application Support/FaceTime"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.facetimeCameraSurface = FacetimeCameraSurfaceState(
            facetimeAppPaths: a, avConferencePaths: b, facetimePrefPaths: c,
            facetimeSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
