import Darwin
import Foundation
import Testing
@testable import RootstockBlueIntegrations

@Suite(.serialized) struct UnifiedLogsSidecarTests {
    @Test func statusAndResolutionRequireARealExecutableFile() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }

        let regular = scratch.appendingPathComponent("sidecar")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: regular)

        setBinaryEnvironment(regular)
        #expect(UnifiedLogsSidecar.status() == .binaryMissing(path: regular.path))
        #expect(UnifiedLogsSidecar.resolveBinary() == nil)

        #expect(chmod(regular.path, S_IRUSR | S_IWUSR | S_IXUSR) == 0)
        #expect(UnifiedLogsSidecar.status() == .ready(path: regular.path))
        #expect(UnifiedLogsSidecar.resolveBinary() == regular)

        let directory = scratch.appendingPathComponent("directory", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        setBinaryEnvironment(directory)
        #expect(UnifiedLogsSidecar.status() == .binaryMissing(path: directory.path))
        #expect(UnifiedLogsSidecar.resolveBinary() == nil)

        let link = scratch.appendingPathComponent("sidecar-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: regular)
        setBinaryEnvironment(link)
        #expect(UnifiedLogsSidecar.status() == .binaryMissing(path: link.path))
        #expect(UnifiedLogsSidecar.resolveBinary() == nil)
    }

    @Test func parseDrainsLargeSidecarOutputAndPublishesWithoutClobbering() throws {
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

        #expect(throws: Never.self) { try UnifiedLogsSidecar.parse(logarchive: archive, outputJSONL: output) }
        #expect(try Data(contentsOf: output) == Data("sidecar-output".utf8))

        let original = Data("preserve".utf8)
        try original.write(to: output)
        #expect(throws: (any Error).self) { try UnifiedLogsSidecar.parse(logarchive: archive, outputJSONL: output) }
        #expect(try Data(contentsOf: output) == original)
    }

    @Test func parseSurfacesNonzeroStderrAndRejectsCaseOutputAliases() throws {
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

        do {
            _ = try UnifiedLogsSidecar.parse(logarchive: archive, outputJSONL: scratch.appendingPathComponent("failure.jsonl"))
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(error.localizedDescription.contains("sidecar failure"))
        }

        let successfulSidecar = try makeSidecar(
            at: scratch.appendingPathComponent("successful-sidecar"),
            body: "printf 'sidecar-output' > \"$3\""
        )
        setBinaryEnvironment(successfulSidecar)
        let package = scratch.appendingPathComponent("case.rsbcase", isDirectory: true)
        try FileManager.default.createDirectory(at: package, withIntermediateDirectories: true)
        #expect(throws: (any Error).self) { try UnifiedLogsSidecar.parse(logarchive: archive, outputJSONL: package.appendingPathComponent("inside.jsonl")) }

        let alias = scratch.appendingPathComponent("case-alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: package)
        #expect(throws: (any Error).self) { try UnifiedLogsSidecar.parse(logarchive: archive, outputJSONL: alias.appendingPathComponent("inside.jsonl")) }
    }

    @Test func parseRejectsArchiveFilesAndLinks() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        setBinaryEnvironment(try makeSidecar(at: scratch.appendingPathComponent("sidecar"), body: "exit 0"))

        let file = scratch.appendingPathComponent("not-an-archive")
        try Data().write(to: file)
        #expect(throws: (any Error).self) { try UnifiedLogsSidecar.parse(logarchive: file, outputJSONL: scratch.appendingPathComponent("output.jsonl")) }

        let archive = try makeArchive(in: scratch)
        let alias = scratch.appendingPathComponent("archive-alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: archive)
        #expect(throws: (any Error).self) { try UnifiedLogsSidecar.parse(logarchive: alias, outputJSONL: scratch.appendingPathComponent("output.jsonl")) }
    }

    @Test func parseEnforcesOutputLimitAndCleansIncompleteOutput() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        setBinaryEnvironment(try makeSidecar(at: scratch.appendingPathComponent("sidecar"), body: "yes x | head -c 4096 > \"$3\""))
        let output = scratch.appendingPathComponent("output.jsonl")

        #expect(throws: (any Error).self) { try UnifiedLogsSidecar.parse(
                logarchive: makeArchive(in: scratch),
                outputJSONL: output,
                limits: .init(maximumRuntime: 2, maximumOutputBytes: 64)
            ) }
        #expect(!(FileManager.default.fileExists(atPath: output.path)))
        #expect(!(try FileManager.default.contentsOfDirectory(atPath: scratch.path).contains { $0.contains(".output.jsonl.rootstock-uls-") }))
    }

    @Test func parseTerminatesAndReapsSidecarsThatExceedRuntimeLimit() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        setBinaryEnvironment(try makeSidecar(
            at: scratch.appendingPathComponent("sidecar"),
            body: "trap '' TERM\nwhile :; do :; done"
        ))
        let output = scratch.appendingPathComponent("output.jsonl")

        do {
            _ = try UnifiedLogsSidecar.parse(
                logarchive: makeArchive(in: scratch),
                outputJSONL: output,
                limits: .init(maximumRuntime: 0.02, maximumOutputBytes: 1_024)
            )
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(error.localizedDescription.contains("runtime limit"))
        }
        #expect(!(FileManager.default.fileExists(atPath: output.path)))
    }

    @Test func parseClosesInheritedPipesWhenWrapperExitsBeforeDescendant() throws {
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

        #expect(throws: Never.self) { try UnifiedLogsSidecar.parse(logarchive: makeArchive(in: scratch), outputJSONL: output) }
        #expect(Date().timeIntervalSince(startedAt) < 0.5)
        #expect(FileManager.default.fileExists(atPath: output.path))
    }

    @Test func parseQuiescesDelayedDescendantWriterBeforePublication() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let previous = ProcessInfo.processInfo.environment[UnifiedLogsSidecar.binaryEnvironmentKey]
        defer { restoreBinaryEnvironment(previous) }
        setBinaryEnvironment(try makeSidecar(
            at: scratch.appendingPathComponent("sidecar"),
            body: "(sleep 0.2; printf 'late oversized descendant output' > \"$3\") &\nexit 0"
        ))
        let output = scratch.appendingPathComponent("output.jsonl")

        #expect(throws: Never.self) { try UnifiedLogsSidecar.parse(
                logarchive: makeArchive(in: scratch),
                outputJSONL: output,
                limits: .init(maximumRuntime: 2, maximumOutputBytes: 8)
            ) }
        let published = try Data(contentsOf: output)
        #expect(published == Data())
        usleep(350_000)
        #expect(try Data(contentsOf: output) == published)
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
        #expect(chmod(url.path, S_IRUSR | S_IWUSR | S_IXUSR) == 0)
        return url
    }

    private func makeArchive(in scratch: URL) throws -> URL {
        let archive = scratch.appendingPathComponent("fixture.logarchive", isDirectory: true)
        try FileManager.default.createDirectory(at: archive, withIntermediateDirectories: true)
        return archive
    }
}
