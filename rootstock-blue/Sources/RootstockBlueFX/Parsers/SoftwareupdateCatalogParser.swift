public struct SoftwareupdateCatalogParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "SUCAT", tier: .tier2, description: "Software Update catalog markers"),
        fileStem: "softwareupdate_catalog",
        fieldPrefix: "sucat",
        eventType: "softwareupdate.catalog",
        defaultRiskTag: "softwareupdate_surface",
        defaultNotes: "Software Update catalog markers - never points SUS catalogs at attacker mirrors or tampers with update plists"
    )

    public init() {}
}
