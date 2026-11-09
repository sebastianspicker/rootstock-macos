/// Ordered macOS major releases, oldest first. Apple went from 15 straight to 26.
// shortcut: list is updated by hand each macOS release, add the new major here
public enum MacOSReleases {
    public static let majors = [11, 12, 13, 14, 15, 26, 27]

    public static var current: Int { majors[majors.count - 1] }

    /// Number of listed releases newer than `major`: the index difference for a listed major, 0 for a
    /// major newer than the list. An unlisted major counts every listed release newer than it:
    /// 10 → 7, and the never-shipped 16-25 → 2 (same as 15).
    public static func releasesBehind(major: Int) -> Int {
        majors.filter { $0 > major }.count
    }
}
