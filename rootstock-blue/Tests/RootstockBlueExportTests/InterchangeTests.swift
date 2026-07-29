import XCTest
@testable import RootstockBlueExport
@testable import RootstockBlueCase
@testable import RootstockBlueCore

final class InterchangeTests: XCTestCase {
    func testImportZipIsDisabledWithoutChangingExistingCaseArtifacts() throws {
        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("cf-zip-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: scratch) }

        let caseURL = scratch.appendingPathComponent("import.rsbcase")
        let pkg = try CasePackage.create(at: caseURL, name: "import-test")
        let importURL = pkg.artifactsURL.appendingPathComponent("import", isDirectory: true)
        try FileManager.default.createDirectory(at: importURL, withIntermediateDirectories: true)
        let sentinelURL = importURL.appendingPathComponent("existing-sentinel.txt")
        try Data("unchanged".utf8).write(to: sentinelURL)
        let eventsBefore = try pkg.loadAllEvents()

        XCTAssertThrowsError(
            try Interchange.importCollectionZip(
                at: scratch.appendingPathComponent("collection.zip"),
                into: pkg
            )
        ) { error in
            XCTAssertEqual(
                error.localizedDescription,
                "Not implemented: ZIP archive import is disabled in this alpha. Parse an already-extracted artifact tree with parse."
            )
        }

        XCTAssertEqual(try Data(contentsOf: sentinelURL), Data("unchanged".utf8))
        XCTAssertEqual(
            try FileManager.default.contentsOfDirectory(atPath: importURL.path),
            ["existing-sentinel.txt"]
        )
        XCTAssertEqual(try pkg.loadAllEvents().count, eventsBefore.count)
    }
}
