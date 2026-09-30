/// QuickLook thumbnail cache residual depth markers (red↔blue pair).
/// Honesty: never dumps QuickLook thumbnail bitmap contents as secret material.
public struct QuicklookCacheDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "QUICKLOOKCACHE", tier: .tier2, description: "QuickLook cache depth markers"),
        fileStem: "quicklook_cache_depth",
        fieldPrefix: "qlcache",
        eventType: "quicklook.cache",
        defaultRiskTag: "quicklook_surface",
        defaultNotes: "QuickLook cache depth markers - never dumps QuickLook thumbnail bitmap contents as secret material"
    )

    public init() {}
}
