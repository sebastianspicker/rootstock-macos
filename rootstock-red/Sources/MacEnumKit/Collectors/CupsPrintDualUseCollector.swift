import Foundation
import RootstockCore

/// CUPS / printer dual-use residual surface (Wave-13).
///
/// Research basis: public 2025–26 macOS CUPS printer dual-use tradecraft research.
/// Safety and behavior: typed path inventory only; never submits print jobs or reconfigures CUPS remotely.
public struct CupsPrintDualUseCollector: Collector {
    public static let id = "collect.cups_print_dualuse"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "CUPS printer dual-use: path presence only - never submits print jobs or reconfigures CUPS remotely",
        ]
        var a: [String] = []
        for path in ["/usr/sbin/cupsd",
            "/System/Library/LaunchDaemons/org.cups.cupsd.plist",
            "/Library/Printers"] where fm.fileExists(atPath: path) {
            a.append(path)
            notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/etc/cups",
            "/private/etc/cups",
            "/Library/Preferences/org.cups.PrintingPrefs.plist"] where fm.fileExists(atPath: path) {
            b.append(path)
            notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/usr/bin/lp",
            "/usr/bin/lpr",
            "/usr/sbin/cupsctl"] where fm.fileExists(atPath: path) {
            c.append(path)
            notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted()
        b = Array(Set(b)).sorted()
        c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.cupsPrintDualUse = CupsPrintDualUseState(
            cupsDaemonPaths: a,
            ppdConfigPaths: b,
            printToolPaths: c,
            printSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
