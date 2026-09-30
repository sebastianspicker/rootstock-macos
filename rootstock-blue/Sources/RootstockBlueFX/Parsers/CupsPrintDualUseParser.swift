/// CUPS / printer dual-use residual surface markers (red↔blue pair).
/// Honesty: never submits print jobs or reconfigures CUPS remotely.
public struct CupsPrintDualUseParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "CUPSPRINTDUAL", tier: .tier2, description: "CUPS printer dual-use surface markers"),
        fileStem: "cups_print_dualuse",
        fieldPrefix: "cups",
        eventType: "cups.print",
        defaultRiskTag: "print_surface",
        defaultNotes: "CUPS printer dual-use markers - never submits print jobs or reconfigures CUPS remotely"
    )

    public init() {}
}
