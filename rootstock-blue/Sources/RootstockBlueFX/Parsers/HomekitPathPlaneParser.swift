public struct HomekitPathPlaneParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "HKPATH", tier: .tier2, description: "HomeKit path plane markers"),
        fileStem: "homekit_path_plane",
        fieldPrefix: "hkpath",
        eventType: "homekit.path",
        defaultRiskTag: "homekit_surface",
        defaultNotes: "HomeKit path plane markers - never enumerates HomeKit accessory secrets or pairs devices"
    )

    public init() {}
}
