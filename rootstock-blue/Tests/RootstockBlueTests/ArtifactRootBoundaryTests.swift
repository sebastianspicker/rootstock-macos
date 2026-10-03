import Foundation
import Testing
@testable import RootstockBlueFX

@Suite struct ArtifactRootBoundaryTests {
    @Test func externalLinksAreRejectedAndContainedLinksRemainReadable() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let evidence = scratch.appendingPathComponent("evidence", isDirectory: true)
        let outside = scratch.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: evidence, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let outsideFile = outside.appendingPathComponent("secret.txt")
        try Data("outside".utf8).write(to: outsideFile)
        let containedFile = evidence.appendingPathComponent("contained.txt")
        try Data("inside".utf8).write(to: containedFile)
        try FileManager.default.createSymbolicLink(
            at: evidence.appendingPathComponent("external.txt"),
            withDestinationURL: outsideFile
        )
        try FileManager.default.createSymbolicLink(
            at: evidence.appendingPathComponent("internal.txt"),
            withDestinationURL: containedFile
        )

        let root = ArtifactRoot(root: evidence)
        #expect(root.firstExisting(["external.txt"]) == nil)
        #expect(root.firstExisting(["internal.txt"])?.lastPathComponent == "internal.txt")
        #expect(!root.enumerate { _ in true }.contains { $0.lastPathComponent == "external.txt" })
    }

    @Test func sqliteReaderRejectsLinkedJournalSidecars() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let database = scratch.appendingPathComponent("History.db")
        let outside = scratch.appendingPathComponent("outside")
        try Data().write(to: database)
        try Data("not evidence".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(
            atPath: database.path + "-wal",
            withDestinationPath: outside.path
        )

        #expect(throws: (any Error).self) { try SQLiteReader(url: database) }
    }
}
