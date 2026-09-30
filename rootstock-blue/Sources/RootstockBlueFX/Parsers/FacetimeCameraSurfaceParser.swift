public struct FacetimeCameraSurfaceParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "FTCAM", tier: .tier2, description: "FaceTime camera dual-use markers"),
        fileStem: "facetime_camera_surface",
        fieldPrefix: "ftcam",
        eventType: "facetime.camera",
        defaultRiskTag: "facetime_surface",
        defaultNotes: "FaceTime camera dual-use markers - never activates camera/mic or dumps FaceTime call history contents"
    )

    public init() {}
}
