import Foundation
import Testing
@testable import RootstockBlueCase

@Suite struct CaseReadBoundaryTests {
    @Test func publicEventLoadRejectsCaseTampering() throws {
        let scratch = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: scratch) }
        let package = try CasePackage.create(at: scratch.appendingPathComponent("case.rsbcase"))
        try package.appendEvent(sampleEvent(), stream: "es")
        let eventFile = try #require(
            FileManager.default.contentsOfDirectory(
                at: package.eventsESURL,
                includingPropertiesForKeys: nil
            ).first
        )
        let handle = try FileHandle(forWritingTo: eventFile)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data(" \n".utf8))
        try handle.close()

        #expect(throws: (any Error).self) { try package.loadAllEvents() }
    }
}
