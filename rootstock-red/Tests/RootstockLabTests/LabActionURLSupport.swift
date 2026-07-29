import XCTest
@testable import RootstockCore
@testable import RootstockLab

extension URL {
    var isEmptyDirectory: Bool {
        let contents = try? FileManager.default.contentsOfDirectory(atPath: path)
        return (contents ?? []).isEmpty
    }
}
