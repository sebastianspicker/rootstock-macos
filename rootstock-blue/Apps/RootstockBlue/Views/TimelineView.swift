import SwiftUI

struct CaseTimelineView: View {
    var body: some View {
        WorkspacePage(
            eyebrow: "Normalized evidence",
            title: "Case timeline",
            summary: "Review the ordered merge of live ES events, offline parsers, and unified-log evidence using stable entity identifiers."
        ) {
            MetricStrip(metrics: [
                WorkspaceMetric(label: "Events", value: "0", tone: .neutral),
                WorkspaceMetric(label: "Sources", value: "0", tone: .neutral),
                WorkspaceMetric(label: "Earliest", value: "—", tone: .neutral),
                WorkspaceMetric(label: "Latest", value: "—", tone: .neutral),
            ])

            InstrumentSection("Event stream", detail: "Chronological") {
                EmptyEvidenceView(
                    title: "No events yet",
                    description: "Record a session or parse an artifact tree into the current case.",
                    systemImage: "timeline.selection"
                )
            }

            CommandLine(command: "rootstock-blue timeline ./demo.rsbcase --limit 40")
        }
    }
}
