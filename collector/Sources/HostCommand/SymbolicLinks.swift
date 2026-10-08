import Darwin

/// `lstat`-based link checks for directory walks inside untrusted bundles and profiles.
public enum SymbolicLinks {
    /// True when `path` itself (not its target) is a symbolic link.
    public static func isLink(atPath path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK
    }
}
