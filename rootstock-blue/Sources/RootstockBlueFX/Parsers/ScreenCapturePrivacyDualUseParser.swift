/// ScreenCapture / screenshot privacy dual-use depth markers (red↔blue pair).
/// Honesty: never captures screens or dumps Screen Recording TCC rows.
public struct ScreenCapturePrivacyDualUseParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "SCREENCAPTUREPRIV", tier: .tier2, description: "ScreenCapture privacy dual-use surface markers"),
        fileStem: "screencapture_privacy_dualuse",
        fieldPrefix: "scpriv",
        eventType: "screencapture.privacy",
        defaultRiskTag: "capture_surface",
        defaultNotes: "ScreenCapture privacy dual-use markers - never captures screens or dumps Screen Recording TCC rows"
    )

    public init() {}
}
