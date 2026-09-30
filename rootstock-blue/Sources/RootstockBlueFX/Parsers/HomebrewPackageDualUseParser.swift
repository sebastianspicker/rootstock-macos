/// Homebrew / third-party package manager dual-use markers (red↔blue pair).
/// Honesty: never installs packages or modifies Homebrew formulae.
public struct HomebrewPackageDualUseParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "HOMEBREWPKG", tier: .tier2, description: "Homebrew package dual-use surface markers"),
        fileStem: "homebrew_package_dualuse",
        fieldPrefix: "brew",
        eventType: "homebrew.package",
        defaultRiskTag: "package_surface",
        defaultNotes: "Homebrew package dual-use markers - never installs packages or modifies Homebrew formulae"
    )

    public init() {}
}
