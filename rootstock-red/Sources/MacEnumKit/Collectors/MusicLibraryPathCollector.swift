import Foundation
import RootstockCore

/// Music / media library path residual (Wave-16).
/// Safety and behavior: path inventory only; never exports Music library media or DRM material.
public struct MusicLibraryPathCollector: Collector {
    public static let id = "collect.music_library_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Music.app",
                    "/System/Library/PrivateFrameworks/iTunesCloud.framework",
                    "/System/Library/Frameworks/MediaPlayer.framework",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Music/Music",
                    NSHomeDirectory() + "/Music/iTunes",
                    NSHomeDirectory() + "/Library/Containers/com.apple.Music",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.Music.plist",
                    "/System/Library/PrivateFrameworks/MediaLibrary.framework",
                ],
                initialHonestyNote: "Music library path: path presence only - never exports Music library media or DRM material"
            )
        )
        var state = CollectedState()
        state.musicLibraryPath = MusicLibraryPathState(
            musicAppPaths: inventory.primaryPaths,
            musicLibraryPaths: inventory.secondaryPaths,
            musicPrefPaths: inventory.tertiaryPaths,
            musicSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
