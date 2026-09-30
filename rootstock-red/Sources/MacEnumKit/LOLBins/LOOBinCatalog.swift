import Foundation
import RootstockCore

/// Loads embedded LOOBins subset and inventories presence on disk.
public struct LOOBinCatalog: Sendable {
    public var entries: [LOOBin]

    public init(entries: [LOOBin] = []) {
        self.entries = entries
    }

    public static func loadEmbedded() throws -> LOOBinCatalog {
        guard let url = Bundle.module.url(forResource: "loobins_subset", withExtension: "json") else {
            // Fallback if resources unavailable in tests
            return LOOBinCatalog(entries: Self.fallbackEntries)
        }
        let data = try Data(contentsOf: url)
        let entries = try JSONDecoder().decode([LOOBin].self, from: data)
        return LOOBinCatalog(entries: entries)
    }

    public func inventory() -> [LOOBinHit] {
        let fm = FileManager.default
        return entries.map { bin in
            LOOBinHit(
                name: bin.name,
                path: bin.path,
                present: fm.isExecutableFile(atPath: bin.path),
                tactics: bin.tactics
            )
        }
    }

    private static let fallbackEntries: [LOOBin] = [
        LOOBin(name: "osascript", path: "/usr/bin/osascript", tactics: ["Execution"]),
        LOOBin(name: "launchctl", path: "/bin/launchctl", tactics: ["Persistence"]),
        LOOBin(name: "security", path: "/usr/bin/security", tactics: ["Credential Access"]),
    ]
}
