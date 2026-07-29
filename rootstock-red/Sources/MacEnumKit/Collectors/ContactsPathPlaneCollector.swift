import Foundation
import RootstockCore

/// Contacts database path residual plane (Wave-16).
/// Safety and behavior: path inventory only; never exports contact cards or dumps AddressBook database contents.
public struct ContactsPathPlaneCollector: Collector {
    public static let id = "collect.contacts_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = ["Contacts path plane: path presence only - never exports contact cards or dumps AddressBook database contents"]
        var a: [String] = []
        for path in ["/System/Applications/Contacts.app",
            "/System/Library/Frameworks/Contacts.framework",
            "/System/Library/PrivateFrameworks/AddressBookCore.framework"] where fm.fileExists(atPath: path) {
            a.append(path); notes.append("a: \(path)")
        }
        var b: [String] = []
        for path in [NSHomeDirectory() + "/Library/Application Support/AddressBook",
            NSHomeDirectory() + "/Library/Containers/com.apple.AddressBook"] where fm.fileExists(atPath: path) {
            b.append(path); notes.append("b: \(path)")
        }
        var c: [String] = []
        for path in [NSHomeDirectory() + "/Library/Preferences/com.apple.AddressBook.plist",
            "/System/Library/PrivateFrameworks/ContactsFoundation.framework"] where fm.fileExists(atPath: path) {
            c.append(path); notes.append("c: \(path)")
        }
        a = Array(Set(a)).sorted(); b = Array(Set(b)).sorted(); c = Array(Set(c)).sorted()
        let surface = !a.isEmpty || b.count >= 1 || c.count >= 2
        var state = CollectedState()
        state.contactsPathPlane = ContactsPathPlaneState(
            contactsAppPaths: a, addressBookPaths: b, contactsPrefPaths: c,
            contactsSurfacePresent: surface, notes: notes
        )
        state.collectorNotes[Self.id] = "a=\(a.count) b=\(b.count) c=\(c.count) surface=\(surface)"
        return state
    }
}
