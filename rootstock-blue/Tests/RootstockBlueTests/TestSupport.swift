import Foundation
import RootstockBlueCore

func makeScratchDirectory() throws -> URL {
    let url = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        .appendingPathComponent(".build", isDirectory: true)
        .appendingPathComponent("rootstock-blue-test-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

func sampleEvent(id: String = "8EBE8993-8CFF-422E-8E6A-5845D60D42EE") -> EventEnvelope {
    EventEnvelope(
        identity: .init(
            id: UUID(uuidString: id)!,
            kind: "fixture.event",
            label: "TEST"
        ),
        capture: .init(
            source: .synthetic,
            eventTime: ISO8601DateFormatter().date(from: "2026-08-27T12:00:00Z")!,
            collectedAt: ISO8601DateFormatter().date(from: "2026-08-27T12:00:01Z")!
        ),
        payload: .init(properties: ["fixture": "true"])
    )
}
