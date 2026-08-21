import Foundation
import RootstockCore

/// Contacts database path residual plane (Wave-16).
/// Safety and behavior: path inventory only; never exports contact cards or dumps AddressBook database contents.
public struct ContactsPathPlaneCollector: Collector {
    public static let id = "collect.contacts_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let inventory = PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: [
                    "/System/Applications/Contacts.app",
                    "/System/Library/Frameworks/Contacts.framework",
                    "/System/Library/PrivateFrameworks/AddressBookCore.framework",
                ],
                secondaryPaths: [
                    NSHomeDirectory() + "/Library/Application Support/AddressBook",
                    NSHomeDirectory() + "/Library/Containers/com.apple.AddressBook",
                ],
                tertiaryPaths: [
                    NSHomeDirectory() + "/Library/Preferences/com.apple.AddressBook.plist",
                    "/System/Library/PrivateFrameworks/ContactsFoundation.framework",
                ],
                initialHonestyNote: "Contacts path plane: path presence only - never exports contact cards or dumps AddressBook database contents"
            )
        )
        var state = CollectedState()
        state.contactsPathPlane = ContactsPathPlaneState(
            contactsAppPaths: inventory.primaryPaths,
            addressBookPaths: inventory.secondaryPaths,
            contactsPrefPaths: inventory.tertiaryPaths,
            contactsSurfacePresent: inventory.surfacePresent,
            notes: inventory.notes
        )
        state.collectorNotes[Self.id] =
            "a=\(inventory.primaryPaths.count) b=\(inventory.secondaryPaths.count) c=\(inventory.tertiaryPaths.count) surface=\(inventory.surfacePresent)"
        return state
    }
}
