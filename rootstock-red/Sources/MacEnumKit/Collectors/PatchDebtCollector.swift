import Foundation
import RootstockCore

/// OS patch-debt / Software Update heuristics for CVE suggester context.
///
/// Research basis: PEASS OS version checks; compliance scanners' "days since patch" ideas.
/// Safety and behavior: typed `PatchDebtState` with major-version lag heuristics; never weaponizes
/// CVEs; never downloads exploit packs; confidence honesty for operators.
public struct PatchDebtCollector: Collector {
    public static let id = "collect.patch_debt"
    public static let cost: CollectorCost = .low

    /// Conservative "known-current major" for lag heuristics (update as product evolves).
    /// Lag is informational only - not a vulnerability claim by itself.
    public static let knownCurrentMajor = 15

    private static let susPlistCandidates: [String] = [
        "/Library/Preferences/com.apple.SoftwareUpdate.plist",
        "/Library/Preferences/com.apple.commerce.plist",
    ]

    private static let installHistoryCandidates: [String] = [
        "/Library/Receipts/InstallHistory.plist",
        "/System/Library/Receipts",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let info = ProcessInfo.processInfo
        let os = info.operatingSystemVersion
        let osVersion = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"

        var notes: [String] = [
            "Patch-debt heuristics only - suggester context, not CVE exploit pack",
        ]
        var lastUpdateHints: [String] = []

        let susPresent = softwareUpdateState(fm, hints: &lastUpdateHints, notes: &notes)
        installHistoryNotes(fm, hints: &lastUpdateHints, notes: &notes)
        let osBuild = systemVersionMetadata(notes: &notes)

        let majorLag = max(0, Self.knownCurrentMajor - os.majorVersion)
        lagNote(majorLag, hostMajor: os.majorVersion, notes: &notes)

        var state = CollectedState()
        state.patchDebt = PatchDebtState(
            osVersion: osVersion,
            osBuild: osBuild,
            softwareUpdatePlistPresent: susPresent,
            lastUpdateHints: lastUpdateHints,
            majorVersionLag: majorLag,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "os=\(osVersion) build=\(osBuild ?? "nil") lag=\(majorLag) sus=\(susPresent.map(String.init(describing:)) ?? "nil")"
        return state
    }

    private func softwareUpdateState(_ fm: FileManager, hints: inout [String], notes: inout [String]) -> Bool? {
        let paths = Self.susPlistCandidates.filter { fm.fileExists(atPath: $0) }
        for path in paths { hints.append("sus_plist:\(path)"); notes.append("Software Update prefs present: \(path)") }
        if paths.isEmpty { notes.append("No Software Update preference plists observed at catalog paths") }
        return !paths.isEmpty
    }

    private func installHistoryNotes(_ fm: FileManager, hints: inout [String], notes: inout [String]) { for path in Self.installHistoryCandidates where fm.fileExists(atPath: path) { hints.append("install_history_path:\(path)"); notes.append("Install history / receipts path present: \(path)") } }
    private func systemVersionMetadata(notes: inout [String]) -> String? { let url = URL(fileURLWithPath: "/System/Library/CoreServices/SystemVersion.plist"); guard let data = try? Data(contentsOf: url), let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { notes.append("SystemVersion.plist unreadable - using ProcessInfo only"); return nil }; let build = dict["ProductBuildVersion"] as? String; if let build { notes.append("ProductBuildVersion=\(build)") }; if let version = dict["ProductUserVisibleVersion"] as? String ?? dict["ProductVersion"] as? String { notes.append("ProductVersion=\(version)") }; return build }
    private func lagNote(_ lag: Int, hostMajor: Int, notes: inout [String]) { notes.append(lag > 0 ? "majorVersionLag=\(lag) (host major \(hostMajor) vs baseline \(Self.knownCurrentMajor))" : "majorVersionLag=0 (host major \(hostMajor) ≥ baseline \(Self.knownCurrentMajor))") }
}
