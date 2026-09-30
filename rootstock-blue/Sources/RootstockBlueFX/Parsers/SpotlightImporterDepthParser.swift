public struct SpotlightImporterDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "SPIMP", tier: .tier2, description: "Spotlight importer depth markers"),
        fileStem: "spotlight_importer_depth",
        fieldPrefix: "spimp",
        eventType: "spotlight.importer",
        defaultRiskTag: "spotlight_importer_surface",
        defaultNotes: "Spotlight importer depth markers - never installs malicious Spotlight importers or dumps mdworker index contents"
    )

    public init() {}
}
