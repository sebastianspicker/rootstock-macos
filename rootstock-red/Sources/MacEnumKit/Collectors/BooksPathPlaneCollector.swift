import Foundation
import RootstockCore

/// Books / EPUB path residual plane.
/// Safety and behavior: path inventory only; never extracts EPUB contents or Books annotations as bulk export.
public struct BooksPathPlaneCollector: Collector {
    public static let id = "collect.books_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Books.app",
                    "/System/Library/PrivateFrameworks/BookLibraryCore.framework",
                ],
                secondaryPaths: [
                    AssessedHome.path + "/Library/Containers/com.apple.iBooksX",
                    AssessedHome.path + "/Library/Mobile Documents/iCloud~com~apple~iBooks",
                ],
                tertiaryPaths: [
                    AssessedHome.path + "/Library/Preferences/com.apple.iBooksX.plist",
                    "/System/Library/PrivateFrameworks/BookKit.framework",
                ],
                initialHonestyNote: "Books path plane: path presence only - never extracts EPUB contents or Books annotations as bulk export"
            )
        )
        var state = CollectedState()
        state.booksPathPlane = BooksPathPlaneState(
            booksAppPaths: inventory.primaryPaths,
            booksContainerPaths: inventory.secondaryPaths,
            booksPrefPaths: inventory.tertiaryPaths,
            booksSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
