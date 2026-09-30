public struct ShortcutsIcloudSyncParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "SCICLOUD", tier: .tier2, description: "Shortcuts iCloud sync markers"),
        fileStem: "shortcuts_icloud_sync",
        fieldPrefix: "scicloud",
        eventType: "shortcuts.icloud",
        defaultRiskTag: "shortcuts_icloud_surface",
        defaultNotes: "Shortcuts iCloud sync markers - never executes Shortcuts or dumps iCloud-synced automation databases"
    )

    public init() {}
}
