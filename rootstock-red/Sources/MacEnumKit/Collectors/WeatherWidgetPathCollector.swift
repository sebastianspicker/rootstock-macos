import Foundation
import RootstockCore

/// Weather / widget data residual plane (Wave-16).
/// Safety and behavior: path inventory only; never dumps weather personalization data or widget timeline contents.
public struct WeatherWidgetPathCollector: Collector {
    public static let id = "collect.weather_widget_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Weather widget residual: path presence only - never dumps weather personalization data or widget timeline contents"]
        var a: [String] = []
        for path in ["/System/Applications/Weather.app",
            "/System/Library/PrivateFrameworks/WeatherFoundation.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Containers/com.apple.weather",
            NSHomeDirectory() + "/Library/Group Containers/group.com.apple.weather"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.weather.plist",
            "/System/Library/PrivateFrameworks/ChronoServices.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.weatherWidgetPath = WeatherWidgetPathState(
            weatherAppPaths: a, weatherContainerPaths: b, widgetServicePaths: c,
            weatherSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
