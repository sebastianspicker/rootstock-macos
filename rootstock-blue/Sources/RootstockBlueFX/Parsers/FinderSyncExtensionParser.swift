public struct FinderSyncExtensionParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "FNDSYNC", tier: .tier2, description: "Finder Sync dual-use markers"),
        fileStem: "finder_sync_extension",
        fieldPrefix: "fndsync",
        eventType: "finder.sync_ext",
        defaultRiskTag: "finder_sync_surface",
        defaultNotes: "Finder Sync dual-use markers - never installs Finder Sync extensions or rewrites Finder preferences for abuse"
    )

    public init() {}
}
