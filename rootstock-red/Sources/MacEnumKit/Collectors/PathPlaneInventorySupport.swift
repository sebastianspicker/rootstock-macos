import Foundation

struct PathPlaneInventorySpec {
    let primaryPaths: [String]
    let secondaryPaths: [String]
    let tertiaryPaths: [String]
    let initialHonestyNote: String
}

struct PathPlaneInventoryResult {
    let primaryPaths: [String]
    let secondaryPaths: [String]
    let tertiaryPaths: [String]
    let surfacePresent: Bool
    let notes: [String]
}

enum PathPlaneInventorySupport {
    static func collect(
        spec: PathPlaneInventorySpec,
        pathExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
    ) -> PathPlaneInventoryResult {
        let primaryPaths = normalizedExistingPaths(spec.primaryPaths, pathExists: pathExists)
        let secondaryPaths = normalizedExistingPaths(spec.secondaryPaths, pathExists: pathExists)
        let tertiaryPaths = normalizedExistingPaths(spec.tertiaryPaths, pathExists: pathExists)
        let surfacePresent = !primaryPaths.isEmpty || secondaryPaths.count >= 1 || tertiaryPaths.count >= 2
        let notes = [spec.initialHonestyNote]
            + primaryPaths.map { "a: \($0)" }
            + secondaryPaths.map { "b: \($0)" }
            + tertiaryPaths.map { "c: \($0)" }

        return PathPlaneInventoryResult(
            primaryPaths: primaryPaths,
            secondaryPaths: secondaryPaths,
            tertiaryPaths: tertiaryPaths,
            surfacePresent: surfacePresent,
            notes: notes
        )
    }

    private static func normalizedExistingPaths(
        _ paths: [String],
        pathExists: (String) -> Bool
    ) -> [String] {
        Array(Set(paths.filter(pathExists))).sorted()
    }
}
