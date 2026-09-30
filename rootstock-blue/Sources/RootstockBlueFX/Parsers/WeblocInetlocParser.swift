/// Webloc / Internet Location file delivery markers (red↔blue pair).
///
/// Honesty: never crafts phishing webloc/inetloc payloads or rewrites Internet Location files.
public struct WeblocInetlocParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "WEBLOCINETLOC", tier: .tier2, description: "Webloc/inetloc delivery surface markers"),
        fileStem: "webloc_inetloc_delivery",
        fieldPrefix: "webloc",
        eventType: "webloc.delivery",
        defaultRiskTag: "delivery_surface",
        defaultNotes: "Webloc/inetloc delivery markers - never crafts phishing webloc/inetloc payloads or rewrites Internet Location files",
        keys: .extended
    )

    public init() {}
}
