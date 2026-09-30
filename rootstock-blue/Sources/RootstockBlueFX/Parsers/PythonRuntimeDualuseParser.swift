/// Python runtime dual-use residual surface markers (red↔blue pair).
/// Honesty: never executes third-party Python payloads or drops malicious site-packages.
public struct PythonRuntimeDualuseParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "PYTHONRUNTIME", tier: .tier2, description: "Python runtime dual-use markers"),
        fileStem: "python_runtime_dualuse",
        fieldPrefix: "pyrun",
        eventType: "python.runtime",
        defaultRiskTag: "python_surface",
        defaultNotes: "Python runtime dual-use markers - never executes third-party Python payloads or drops malicious site-packages"
    )

    public init() {}
}
