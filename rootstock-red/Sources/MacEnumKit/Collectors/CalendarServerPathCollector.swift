import Foundation
import RootstockCore

/// Calendar server / CalDAV residual surface (Wave-16).
/// Safety and behavior: path inventory only; never reads calendar event bodies or credentials from CalDAV stores.
public struct CalendarServerPathCollector: Collector {
    public static let id = "collect.calendar_server_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Library/PrivateFrameworks/CalendarDaemon.framework",
                    "/System/Library/PrivateFrameworks/CalDAV.framework",
                    "/usr/libexec/calaccessd",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Calendars",
                    NSHomeDirectory() + "/Library/Containers/com.apple.iCal",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.iCal.plist",
                    "/System/Library/LaunchAgents/com.apple.CalendarAgent.plist",
                ],
                initialHonestyNote: "Calendar CalDAV residual: path presence only - never reads calendar event bodies or credentials from CalDAV stores"
            )
        )
        var state = CollectedState()
        state.calendarServerPath = CalendarServerPathState(
            caldavFrameworkPaths: inventory.primaryPaths,
            calendarsStorePaths: inventory.secondaryPaths,
            calendarAgentPaths: inventory.tertiaryPaths,
            caldavSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
