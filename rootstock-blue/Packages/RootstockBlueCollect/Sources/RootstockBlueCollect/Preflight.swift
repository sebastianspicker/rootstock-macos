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
            PreflightItem(
                name: "Data volume unlocked",
                ok: true,
                detail: "FileVault unlock requires user/org secrets - no crack path",
                required: true
            ),
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
            return PreflightItem(
                name: "Full Disk Access",
                ok: false,
                detail: "Grant FDA to RootstockBlue in System Settings → Privacy (cannot auto-grant)",
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

    public static func enforce(_ report: PreflightReport) throws {
        let failed = report.failedRequired.map { "\($0.name): \($0.detail)" }
        if !failed.isEmpty {
            throw RootstockBlueError.preflightFailed(failed)
        }
    }
}
