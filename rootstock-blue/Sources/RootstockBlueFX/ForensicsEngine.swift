import Foundation
import RootstockBlueCore

/// Offline forensics engine - **no Endpoint Security dependency**.
public struct ForensicsEngine: Sendable {
    public var runtime: PluginRuntime

    public init(runtime: PluginRuntime = PluginRuntime()) {
        self.runtime = runtime
    }

    public func parse(source: ImageSource, plugins: [String]? = nil) throws -> [EventEnvelope] {
        try parseCollectingFailures(source: source, plugins: plugins).events
    }

    /// Parses and returns per-artifact read/parse failure notes alongside the events.
    /// Failure notes come from the process-wide `ArtifactIO.failures` log, which is reset at the start of each run.
    public func parseCollectingFailures(
        source: ImageSource,
        plugins: [String]? = nil
    ) throws -> (events: [EventEnvelope], failures: [String]) {
        try source.validate()
        let selected: [any ArtifactParser]
        if let plugins {
            selected = runtime.parsers.filter { plugins.contains($0.manifest.id) }
        } else {
            selected = runtime.parsers
        }
        ArtifactIO.failures.reset()
        var all: [EventEnvelope] = []
        for parser in selected {
            let events = try parser.parse(source: source)
            all.append(contentsOf: events)
        }
        return (TimelineMerger.merge(all), ArtifactIO.failures.snapshot())
    }

    /// Emit parsed events through an application-provided sink.
    @discardableResult
    public func parse(source: ImageSource, into sink: any EventSink) throws -> Int {
        let (events, failures) = try parseCollectingFailures(source: source)
        let failureNote = failures.isEmpty ? "" : " failed_artifacts=\(failures.count)"
        try sink.append(
            events,
            custody: EventCustodyNote(
                action: "parse",
                detail: "Parsed \(events.count) events from \(source.url.path) plugins=\(runtime.parserIDs().joined(separator: ","))\(failureNote)"
            )
        )
        return events.count
    }
}
