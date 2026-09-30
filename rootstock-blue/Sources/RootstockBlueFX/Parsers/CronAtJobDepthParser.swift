/// Cron / at job dual-use residual depth markers (red↔blue pair).
/// Honesty: never installs cron or at jobs outside the lab root.
public struct CronAtJobDepthParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "CRONATJOB", tier: .tier2, description: "Cron/at job depth markers"),
        fileStem: "cron_at_job_depth",
        fieldPrefix: "cronat",
        eventType: "cron.at_job",
        defaultRiskTag: "cron_at_surface",
        defaultNotes: "Cron/at job depth markers - never installs cron or at jobs outside the lab root"
    )

    public init() {}
}
