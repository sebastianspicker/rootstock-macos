/// Screen Sharing / ARD residual depth markers (red↔blue pair).
/// Honesty: never enables Screen Sharing or ARD, never connects to remote desktops.
public struct ScreenSharingArdDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "SCREENSHARINGARD", tier: .tier2, description: "Screen Sharing ARD depth markers"),
        fileStem: "screen_sharing_ard_depth",
        fieldPrefix: "ardss",
        eventType: "ard.screen_sharing",
        defaultRiskTag: "ard_surface",
        defaultNotes: "Screen Sharing ARD depth markers - never enables Screen Sharing or ARD, never connects to remote desktops"
    )

    public init() {}
}
