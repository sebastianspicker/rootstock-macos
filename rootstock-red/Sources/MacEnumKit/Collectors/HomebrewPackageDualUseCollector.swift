import Foundation
import RootstockCore

/// Homebrew / third-party package manager dual-use (Wave-13).
///
/// Research basis: public 2025–26 macOS Homebrew package dual-use tradecraft research.
/// Safety and behavior: typed path inventory only; never installs packages or modifies Homebrew formulae.
public struct HomebrewPackageDualUseCollector: Collector {
    public static let id = "collect.homebrew_package_dualuse"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Homebrew package dual-use: path presence only - never installs packages or modifies Homebrew formulae",
        ]
        var a: [String] = []
        for path in ["/opt/homebrew/bin/brew",
            "/usr/local/bin/brew",
            NSHomeDirectory() + "/.linuxbrew/bin/brew"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/opt/homebrew/Cellar",
            "/usr/local/Cellar",
            "/opt/homebrew/Caskroom"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/opt/homebrew/Library/Taps",
            "/usr/local/Homebrew/Library/Taps",
            NSHomeDirectory() + "/Library/Caches/Homebrew"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.homebrewPackageDualUse = HomebrewPackageDualUseState(
            brewBinaryPaths: a,
            cellarPaths: b,
            tapPaths: c,
            packageSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
