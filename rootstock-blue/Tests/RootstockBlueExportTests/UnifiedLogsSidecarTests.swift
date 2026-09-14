import Darwin
import Foundation
import XCTest
@testable import RootstockBlueIntegrations

final class UnifiedLogsSidecarTests: XCTestCase {
    func testStatusAndResolutionRequireARealExecutableFile() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }

        let regular = scratch.appendingPathComponent("sidecar")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: regular)

        setBinaryEnvironment(regular)
        XCTAssertEqual(UnifiedLogsSidecar.status(), .binaryMissing(path: regular.path))
        XCTAssertNil(UnifiedLogsSidecar.resolveBinary())

        XCTAssertEqual(chmod(regular.path, S_IRUSR | S_IWUSR | S_IXUSR), 0)
        XCTAssertEqual(UnifiedLogsSidecar.status(), .ready(path: regular.path))
        XCTAssertEqual(UnifiedLogsSidecar.resolveBinary(), regular)

        let directory = scratch.appendingPathComponent("directory", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        setBinaryEnvironment(directory)
        XCTAssertEqual(UnifiedLogsSidecar.status(), .binaryMissing(path: directory.path))
        XCTAssertNil(UnifiedLogsSidecar.resolveBinary())

        let link = scratch.appendingPathComponent("sidecar-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: regular)
        setBinaryEnvironment(link)
        XCTAssertEqual(UnifiedLogsSidecar.status(), .binaryMissing(path: link.path))
        XCTAssertNil(UnifiedLogsSidecar.resolveBinary())
    }

    func testParseDrainsLargeSidecarOutputAndPublishesWithoutClobbering() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        let sidecar = try makeSidecar(
            at: scratch.appendingPathComponent("sidecar"),
            body: "yes stdout | head -c 131072\nyes stderr | head -c 131072 >&2\nprintf 'sidecar-output' > \"$3\""
        )
        setBinaryEnvironment(sidecar)
        let archive = try makeArchive(in: scratch)
        let output = scratch.appendingPathComponent("result.jsonl")

        XCTAssertNoThrow(try UnifiedLogsSidecar.parse(logarchive: archive, outputJSONL: output))
        XCTAssertEqual(try Data(contentsOf: output), Data("sidecar-output".utf8))

        let original = Data("preserve".utf8)
        try original.write(to: output)
        XCTAssertThrowsError(try UnifiedLogsSidecar.parse(logarchive: archive, outputJSONL: output))
        XCTAssertEqual(try Data(contentsOf: output), original)
    }

    func testParseSurfacesNonzeroStderrAndRejectsCaseOutputAliases() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        let failingSidecar = try makeSidecar(
            at: scratch.appendingPathComponent("failing-sidecar"),
            body: "printf 'sidecar failure' >&2\nexit 9"
        )
        setBinaryEnvironment(failingSidecar)
        let archive = try makeArchive(in: scratch)

        XCTAssertThrowsError(try UnifiedLogsSidecar.parse(logarchive: archive, outputJSONL: scratch.appendingPathComponent("failure.jsonl"))) { error in
            XCTAssertTrue(error.localizedDescription.contains("sidecar failure"))
        }

        let successfulSidecar = try makeSidecar(
            at: scratch.appendingPathComponent("successful-sidecar"),
            body: "printf 'sidecar-output' > \"$3\""
        )
        setBinaryEnvironment(successfulSidecar)
        let package = scratch.appendingPathComponent("case.rsbcase", isDirectory: true)
        try FileManager.default.createDirectory(at: package, withIntermediateDirectories: true)
        XCTAssertThrowsError(try UnifiedLogsSidecar.parse(logarchive: archive, outputJSONL: package.appendingPathComponent("inside.jsonl")))

        let alias = scratch.appendingPathComponent("case-alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: package)
        XCTAssertThrowsError(try UnifiedLogsSidecar.parse(logarchive: archive, outputJSONL: alias.appendingPathComponent("inside.jsonl")))
    }

    func testParseRejectsArchiveFilesAndLinks() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        setBinaryEnvironment(try makeSidecar(at: scratch.appendingPathComponent("sidecar"), body: "exit 0"))

        let file = scratch.appendingPathComponent("not-an-archive")
        try Data().write(to: file)
        XCTAssertThrowsError(try UnifiedLogsSidecar.parse(logarchive: file, outputJSONL: scratch.appendingPathComponent("output.jsonl")))

        let archive = try makeArchive(in: scratch)
        let alias = scratch.appendingPathComponent("archive-alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: archive)
        XCTAssertThrowsError(try UnifiedLogsSidecar.parse(logarchive: alias, outputJSONL: scratch.appendingPathComponent("output.jsonl")))
    }

    func testParseEnforcesOutputLimitAndCleansIncompleteOutput() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        setBinaryEnvironment(try makeSidecar(at: scratch.appendingPathComponent("sidecar"), body: "yes x | head -c 4096 > \"$3\""))
        let output = scratch.appendingPathComponent("output.jsonl")

        XCTAssertThrowsError(
            try UnifiedLogsSidecar.parse(
                logarchive: makeArchive(in: scratch),
                outputJSONL: output,
                limits: .init(maximumRuntime: 2, maximumOutputBytes: 64)
            )
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: scratch.path).contains { $0.contains(".output.jsonl.rootstock-uls-") })
    }

    func testParseTerminatesAndReapsSidecarsThatExceedRuntimeLimit() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        setBinaryEnvironment(try makeSidecar(
            at: scratch.appendingPathComponent("sidecar"),
            body: "trap '' TERM\nwhile :; do :; done"
        ))
        let output = scratch.appendingPathComponent("output.jsonl")

        XCTAssertThrowsError(
            try UnifiedLogsSidecar.parse(
                logarchive: makeArchive(in: scratch),
                outputJSONL: output,
                limits: .init(maximumRuntime: 0.02, maximumOutputBytes: 1_024)
            )
        ) { error in
            XCTAssertTrue(error.localizedDescription.contains("runtime limit"))
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
    }

    func testParseClosesInheritedPipesWhenWrapperExitsBeforeDescendant() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        setBinaryEnvironment(try makeSidecar(
            at: scratch.appendingPathComponent("sidecar"),
            body: "sleep 1 &\nexit 0"
        ))
        let output = scratch.appendingPathComponent("output.jsonl")
        let startedAt = Date()

        XCTAssertNoThrow(try UnifiedLogsSidecar.parse(logarchive: makeArchive(in: scratch), outputJSONL: output))
        XCTAssertLessThan(Date().timeIntervalSince(startedAt), 0.5)
        XCTAssertTrue(FileManager.default.fileExists(atPath: output.path))
    }

    func testParseQuiescesDelayedDescendantWriterBeforePublication() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        setBinaryEnvironment(try makeSidecar(
            at: scratch.appendingPathComponent("sidecar"),
            body: "(sleep 0.2; printf 'late oversized descendant output' > \"$3\") &\nexit 0"
        ))
        let output = scratch.appendingPathComponent("output.jsonl")

        XCTAssertNoThrow(
            try UnifiedLogsSidecar.parse(
                logarchive: makeArchive(in: scratch),
                outputJSONL: output,
                limits: .init(maximumRuntime: 2, maximumOutputBytes: 8)
            )
        )
        let published = try Data(contentsOf: output)
        XCTAssertEqual(published, Data())
        usleep(350_000)
        XCTAssertEqual(try Data(contentsOf: output), published)
    }

    private func setBinaryEnvironment(_ url: URL) {
        setenv(UnifiedLogsSidecar.binaryEnvironmentKey, url.path, 1)
    }

    private func restoreBinaryEnvironment(_ previous: String?) {
        if let previous {
            setenv(UnifiedLogsSidecar.binaryEnvironmentKey, previous, 1)
        } else {
            unsetenv(UnifiedLogsSidecar.binaryEnvironmentKey)
        }
    }

    private func makeSidecar(at url: URL, body: String) throws -> URL {
        try "#!/bin/sh\n\(body)\n".write(to: url, atomically: true, encoding: .utf8)
        XCTAssertEqual(chmod(url.path, S_IRUSR | S_IWUSR | S_IXUSR), 0)
        return url
    }

    private func makeArchive(in scratch: URL) throws -> URL {
        let archive = scratch.appendingPathComponent("fixture.logarchive", isDirectory: true)
        try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true)
        return archive
    }
}
