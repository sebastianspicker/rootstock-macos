import Foundation
import RootstockBlueCore

/// Offline forensics engine - **no Endpoint Security dependency**.
public struct ForensicsEngine: Sendable {
    public var runtime: PluginRuntime

    public init(runtime: PluginRuntime = PluginRuntime()) {
        self.runtime = runtime
    }

    public func parse(source: ImageSource, plugins: [String]? = nil) throws -> [EventEnvelope] {
        let selected: [any ArtifactParser]
        if let plugins {
            selected = runtime.parsers.filter { plugins.contains($0.manifest.id) }
        } else {
            selected = runtime.parsers
        }
        var all: [EventEnvelope] = []
        for parser in selected {
            let events = try parser.parse(source: source)
            all.append(contentsOf: events)
        }
        return TimelineMerger.merge(all)
    }

    /// Emit parsed events through an application-provided sink.
    @discardableResult
    public func parse(source: ImageSource, into sink: any EventSink) throws -> Int {
        let events = try parse(source: source)
        try sink.append(
            events,
            custody: EventCustodyNote(
                action: "parse",
                detail: "Parsed \(events.count) events from \(source.url.path) plugins=\(runtime.parserIDs().joined(separator: ","))"
            )
        )
        return events.count
    }
}
