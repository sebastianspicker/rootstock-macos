import Foundation
import RootstockCore

/// Archive / quarantine third-party extractor surface (Wave-9).
///
/// Research basis: Unit 42 / Jamf third-party archive extractor quarantine non-inheritance research.
/// Safety and behavior: typed `ArchiveQuarantineExtractorState`; never strips quarantine or crafts bypass archives.
public struct ArchiveQuarantineExtractorCollector: Collector {
    public static let id = "collect.archive_quarantine_extractor"
    public static let cost: CollectorCost = .low

    private static let thirdPartyApps: [String] = [
        "/Applications/The Unarchiver.app",
        "/Applications/Keka.app",
        "/Applications/BetterZip.app",
        "/Applications/Archiver.app",
        "/Applications/iZip.app",
        "/Applications/StuffIt Expander.app",
        "/Applications/WinZip.app",
        "/Applications/Commander One.app",
        "/Applications/Path Finder.app",
    ]

    private static let stockExtractors: [String] = [
        "/System/Library/CoreServices/Applications/Archive Utility.app",
        "/System/Library/CoreServices/Archive Utility.app",
        "/usr/bin/ditto",
        "/usr/bin/tar",
        "/usr/bin/unzip",
        "/usr/bin/gzip",
        "/usr/bin/bsdtar",
    ]

    private static let dropHints: [String] = [
        NSHomeDirectory() + "/Downloads",
        NSHomeDirectory() + "/Desktop",
        "/tmp",
        "/var/tmp",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Archive/quarantine extractor surface: path presence only - never strips com.apple.quarantine, never crafts bypass archives",
        ]

        var thirdParty: [String] = []
        for path in Self.thirdPartyApps where fm.fileExists(atPath: path) {
            thirdParty.append(path)
            notes.append("third_party_extractor: \(path)")
        }

        var stock: [String] = []
        for path in Self.stockExtractors where fm.fileExists(atPath: path) {
            stock.append(path)
            notes.append("stock_extractor: \(path)")
        }

        var drops: [String] = []
        for path in Self.dropHints where fm.fileExists(atPath: path) {
            drops.append(path)
            notes.append("archive_drop_hint: \(path)")
        }

        thirdParty = Array(Set(thirdParty)).sorted()
        stock = Array(Set(stock)).sorted()
        drops = Array(Set(drops)).sorted()

        // Stock extractors alone are baseline macOS; third-party or multi-stock elevates surface.
        let surface = !thirdParty.isEmpty || stock.count >= 3

        var state = CollectedState()
        state.archiveQuarantineExtractor = ArchiveQuarantineExtractorState(
            thirdPartyExtractorPaths: thirdParty,
            stockExtractorPaths: stock,
            archiveDropHints: drops,
            extractorSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "thirdParty=\(thirdParty.count) stock=\(stock.count) "
            + "drops=\(drops.count) surface=\(surface)"
        return state
    }
}
