import Foundation
import RootstockCore

/// Weather / widget data residual plane (Wave-16).
/// Safety and behavior: path inventory only; never dumps weather personalization data or widget timeline contents.
public struct WeatherWidgetPathCollector: Collector {
    public static let id = "collect.weather_widget_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Weather.app",
                    "/System/Library/PrivateFrameworks/WeatherFoundation.framework",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Containers/com.apple.weather",
                    NSHomeDirectory() + "/Library/Group Containers/group.com.apple.weather",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.weather.plist",
                    "/System/Library/PrivateFrameworks/ChronoServices.framework",
                ],
                initialHonestyNote: "Weather widget residual: path presence only - never dumps weather personalization data or widget timeline contents"
            )
        )
        var state = CollectedState()
        state.weatherWidgetPath = WeatherWidgetPathState(
            weatherAppPaths: inventory.primaryPaths,
            weatherContainerPaths: inventory.secondaryPaths,
            widgetServicePaths: inventory.tertiaryPaths,
            weatherSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
