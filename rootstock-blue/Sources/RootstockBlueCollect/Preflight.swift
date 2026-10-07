/// Preflight - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public struct PreflightItem: Sendable {
    public var name: String
    public var ok: Bool
    public var detail: String
    public var required: Bool

    public init(name: String, ok: Bool, detail: String, required: Bool = true) {
        self.name = name
        self.ok = ok
        self.detail = detail
        self.required = required
    }
}

public struct PreflightReport: Sendable {
    public var items: [PreflightItem]

    public var failedRequired: [PreflightItem] {
        items.filter { $0.required && !$0.ok }
    }

    public var passed: Bool { failedRequired.isEmpty }
}

/// Honest permission checklist - never silent TCC/FDA bypass.
public enum Preflight {
    /// - Parameter offlineFixtureMode: When true, FDA is not required (offline tree / CI).
    public static func check(for pack: CollectionPack, offlineFixtureMode: Bool = false) -> PreflightReport {
        PreflightReport(items: [
            fullDiskAccessItem(pack: pack, offlineFixtureMode: offlineFixtureMode),
            dataVolumeItem(),
            PreflightItem(
                name: "SIP intact",
                ok: true,
                detail: "RootstockBlue does not require disabling SIP for production use",
                required: false
            ),
        ])
    }

    private static func fullDiskAccessItem(
        pack: CollectionPack,
        offlineFixtureMode: Bool
    ) -> PreflightItem {
        if offlineFixtureMode {
            return PreflightItem(
                name: "Full Disk Access",
                ok: true,
                detail: "Offline/fixture mode - FDA not required for offline tree collect",
                required: false
            )
        }
        if pack.requiresFDA {
            let granted = hasFullDiskAccess()
            return PreflightItem(
                name: "Full Disk Access",
                ok: granted,
                detail: granted
                    ? "FDA probe succeeded (TCC-protected file is readable)"
                    : "Grant FDA to RootstockBlue in System Settings → Privacy (cannot auto-grant)",
                required: true
            )
        }
        return PreflightItem(
            name: "Full Disk Access",
            ok: true,
            detail: "Not required for this pack",
            required: false
        )
    }

    /// Probes TCC-protected files with a real open; no probe file readable means FDA is not granted.
    static func hasFullDiskAccess() -> Bool {
        let candidates = [
            NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db",
            "/Library/Application Support/com.apple.TCC/TCC.db",
        ]
        for path in candidates where FileManager.default.isReadableFile(atPath: path) {
            let descriptor = Darwin.open(path, O_RDONLY)
            if descriptor >= 0 {
                _ = Darwin.close(descriptor)
                return true
            }
        }
        return false
    }

    private static func dataVolumeItem() -> PreflightItem {
        let home = NSHomeDirectory()
        if (try? FileManager.default.contentsOfDirectory(atPath: home)) != nil {
            return PreflightItem(
                name: "Data volume unlocked",
                ok: true,
                detail: "Home directory is listable; FileVault unlock requires user/org secrets - no crack path",
                required: true
            )
        }
        return PreflightItem(
            name: "Data volume unlocked",
            ok: false,
            detail: "Cannot list \(home); volume may be locked or inaccessible - no crack path",
            required: true
        )
    }

    public static func enforce(_ report: PreflightReport) throws {
        let failed = report.failedRequired.map { "\($0.name): \($0.detail)" }
        if !failed.isEmpty {
            throw RootstockBlueError.preflightFailed(failed)
        }
    }
}
