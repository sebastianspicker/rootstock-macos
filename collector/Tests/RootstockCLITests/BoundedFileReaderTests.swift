import Darwin
import Foundation
import Testing
@testable import HostCommand

@Suite struct BoundedFileReaderTests {
    @Test func rejectsSpecialAndOversizeFilesWithoutBlocking() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("bounded-reader-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let fifo = root.appendingPathComponent("fixture.fifo")
        #expect(mkfifo(fifo.path, mode_t(S_IRUSR | S_IWUSR)) == 0)
        #expect(throws: BoundedFileReadError.self) {
            try BoundedFileReader.read(path: fifo.path, limit: 8)
        }

        let oversized = root.appendingPathComponent("oversized")
        try Data(repeating: 0x41, count: 9).write(to: oversized)
        #expect(throws: BoundedFileReadError.self) {
            try BoundedFileReader.read(path: oversized.path, limit: 8)
        }
    }
}
