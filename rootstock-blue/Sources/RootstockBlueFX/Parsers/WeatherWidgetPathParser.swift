public struct WeatherWidgetPathParser: SurfaceMarkerParser {
    static let spec = SurfaceMarkerSpec(
        manifest: PluginManifest(id: "WTHRWDG", tier: .tier2, description: "Weather widget residual markers"),
        fileStem: "weather_widget_path",
        fieldPrefix: "wthrwdg",
        eventType: "weather.widget",
        defaultRiskTag: "weather_surface",
        defaultNotes: "Weather widget residual markers - never dumps weather personalization data or widget timeline contents"
    )

    public init() {}
}
