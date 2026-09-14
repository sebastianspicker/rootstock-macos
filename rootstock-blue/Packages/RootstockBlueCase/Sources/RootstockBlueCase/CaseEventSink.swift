import Foundation
import RootstockBlueCore

/// Bridges CasePackage to SessionRecorder / collect writers.
public struct CaseEventSink: EventSink {
    public let package: CasePackage
    public let actor: String
    public let stream: String

    public init(package: CasePackage, actor: String = NSUserName(), stream: String = "es") {
        self.package = package
        self.actor = actor
        self.stream = stream
    }

    public func append(_ event: EventEnvelope) throws {
        try package.appendEvent(event, stream: stream)
    }

    public func append(_ events: [EventEnvelope], custody: EventCustodyNote?) throws {
        try package.appendEventBatch(
            events,
            stream: stream,
            custody: custody.map {
                CustodyEvent(actor: actor, action: $0.action, detail: $0.detail)
            }
        )
    }

    public func noteCustody(action: String, detail: String) throws {
        try package.appendCustody(CustodyEvent(actor: actor, action: action, detail: detail))
    }
}
