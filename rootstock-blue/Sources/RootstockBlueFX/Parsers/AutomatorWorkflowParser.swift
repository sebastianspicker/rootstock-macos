/// Automator workflow delivery residual markers (red↔blue pair).
/// Honesty: never executes Automator workflows or plants malicious .workflow bundles.
public struct AutomatorWorkflowParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "AUTOMATORWF", tier: .tier2, description: "Automator workflow delivery markers"),
        fileStem: "automator_workflow",
        fieldPrefix: "automator",
        eventType: "automator.workflow",
        defaultRiskTag: "workflow_surface",
        defaultNotes: "Automator workflow delivery markers - never executes Automator workflows or plants malicious .workflow bundles"
    )

    public init() {}
}
