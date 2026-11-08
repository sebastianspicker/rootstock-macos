import Foundation

extension FileManager {
    /// `isWritableFile` (access(W_OK)) is true for every path when running as root, which would report
    /// root-owned files like /etc/sudoers as user-writable. As root, judge by owner/mode instead.
    func isWritableByNonRoot(atPath path: String) -> Bool {
        guard geteuid() == 0 else { return isWritableFile(atPath: path) }
        var info = stat()
        guard stat(path, &info) == 0 else { return false }
        return Self.isWritableByNonRoot(ownerUID: info.st_uid, groupID: info.st_gid, mode: info.st_mode)
    }

    static func isWritableByNonRoot(ownerUID: uid_t, groupID: gid_t, mode: mode_t) -> Bool {
        ownerUID != 0 || mode & mode_t(S_IWOTH) != 0 || (mode & mode_t(S_IWGRP) != 0 && groupID != 0)
    }
}
