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
        try package.appendEventJSONL(event, stream: stream)
        try package.insertTimelineEvent(event)
    }

    public func noteCustody(action: String, detail: String) throws {
        try package.appendCustody(CustodyEvent(actor: actor, action: action, detail: detail))
        try package.updateHashes()
    }
}
