import Foundation
import RootstockMacFacts

/// Home of the assessed user: the sudo-invoking user's when run as root, else the process home.
/// The one accessor Red's enumeration and vectors use; Lab paths deliberately keep the process home.
public enum AssessedHome {
    public static var url: URL { AssessedUser.homeDirectory() }
    public static var path: String { url.path }
    public static var userID: uid_t { AssessedUser.userID() }
}
