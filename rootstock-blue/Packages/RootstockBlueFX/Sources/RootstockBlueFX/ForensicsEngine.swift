import Foundation
import RootstockBlueCore
import RootstockBlueCase

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

    public func parse(source: ImageSource, into casePackage: CasePackage, actor: String = NSUserName()) throws -> Int {
        let events = try parse(source: source)
        for event in events {
            try casePackage.appendEventJSONL(event, stream: "es")
            try casePackage.insertTimelineEvent(event)
        }
        try casePackage.appendCustody(
            CustodyEvent(
                actor: actor,
                action: "parse",
                detail: "Parsed \(events.count) events from \(source.url.path) plugins=\(runtime.parserIDs().joined(separator: ","))"
            )
        )
        try casePackage.updateHashes()
        return events.count
    }
}

/// Merge live JSONL + offline parser events already stored in a case.
public enum CaseTimeline {
    public static func merged(from package: CasePackage) throws -> [EventEnvelope] {
        TimelineMerger.merge(try package.loadAllEvents())
    }
}
