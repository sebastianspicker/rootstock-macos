import Foundation
import RootstockCore

/// File Provider domain residual surface (Wave-16).
/// Safety and behavior: path inventory only; never registers malicious File Provider domains or exfiltrates provider caches.
public struct FileproviderDomainCollector: Collector {
    public static let id = "collect.fileprovider_domain"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["File Provider domain: path presence only - never registers malicious File Provider domains or exfiltrates provider caches"]
        var a: [String] = []
        for path in ["/System/Library/Frameworks/FileProvider.framework",
            "/System/Library/PrivateFrameworks/FileProviderDaemon.framework",
            "/usr/libexec/fileproviderd"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Application Support/FileProvider",
            NSHomeDirectory() + "/Library/CloudStorage"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/LaunchAgents/com.apple.FileProvider.plist",
            NSHomeDirectory() + "/Library/Preferences/com.apple.FileProvider.plist"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.fileproviderDomain = FileproviderDomainState(
            fileProviderFrameworkPaths: a, cloudStoragePaths: b, fileProviderLaunchPaths: c,
            fileProviderSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
