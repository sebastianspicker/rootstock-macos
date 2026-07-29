import Foundation
import RootstockCore

/// Software Update catalog residual surface (Wave-16).
/// Safety and behavior: path inventory only; never points SUS catalogs at attacker mirrors or tampers with update plists.
public struct SoftwareupdateCatalogCollector: Collector {
    public static let id = "collect.softwareupdate_catalog"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Software Update catalog: path presence only - never points SUS catalogs at attacker mirrors or tampers with update plists"]
        var a: [String] = []
        for path in ["/usr/sbin/softwareupdate",
            "/System/Library/PrivateFrameworks/SoftwareUpdate.framework",
            "/usr/libexec/softwareupdated"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in ["/Library/Preferences/com.apple.SoftwareUpdate.plist",
            "/Library/Preferences/com.apple.commerce.plist"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in ["/System/Library/LaunchDaemons/com.apple.softwareupdated.plist",
            "/Library/Updates"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.softwareupdateCatalog = SoftwareupdateCatalogState(
            softwareUpdateToolPaths: a, softwareUpdatePrefPaths: b, softwareUpdateDaemonPaths: c,
            softwareUpdateSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
