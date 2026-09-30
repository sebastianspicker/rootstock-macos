/// Font validation / ATS dual-use surface markers (red↔blue pair).
/// Honesty: never installs malicious fonts or disables font validation.
public struct FontValidationDualuseParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "FONTVALIDATION", tier: .tier2, description: "Font validation dual-use markers"),
        fileStem: "font_validation_dualuse",
        fieldPrefix: "fontval",
        eventType: "font.validation",
        defaultRiskTag: "font_surface",
        defaultNotes: "Font validation dual-use markers - never installs malicious fonts or disables font validation"
    )

    public init() {}
}
