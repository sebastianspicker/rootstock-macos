/// Gatekeeper assessment / syspolicyd history depth markers (red↔blue pair).
/// Honesty: never clears Gatekeeper assessments or disables syspolicyd.
public struct GatekeeperAssessmentHistoryParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "GKASSESSMENTHIST", tier: .tier2, description: "Gatekeeper assessment history surface markers"),
        fileStem: "gatekeeper_assessment_history",
        fieldPrefix: "gkh",
        eventType: "gatekeeper.assessment",
        defaultRiskTag: "assessment_surface",
        defaultNotes: "Gatekeeper assessment history markers - never clears Gatekeeper assessments or disables syspolicyd"
    )

    public init() {}
}
