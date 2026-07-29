import SwiftUI

struct DetectionsView: View {
    var body: some View {
        WorkspacePage(
            eyebrow: "Detection review",
            title: "Fixture-backed findings",
            summary: "Evaluate bundled YAML rules against normalized case events. Live stream filtering is not implemented."
        ) {
            MetricStrip(metrics: [
                WorkspaceMetric(label: "Critical", value: "0", tone: .critical),
                WorkspaceMetric(label: "High", value: "0", tone: .warning),
                WorkspaceMetric(label: "Medium", value: "0", tone: .accent),
                WorkspaceMetric(label: "Rules run", value: "0", tone: .neutral),
            ])

            InstrumentSection("Findings", detail: "No rules evaluated") {
                EmptyEvidenceView(
                    title: "No detection results",
                    description: "Run a ruleset against a populated case to review matched evidence here.",
                    systemImage: "shield.lefthalf.filled"
                )
            }

            InstrumentSection("Rule boundary") {
                EvidenceRow(
                    icon: "checkmark.seal",
                    title: "Required fixtures",
                    detail: "Detection content is validated against repository fixtures.",
                    status: "Validated",
                    tone: .verified
                )
                EvidenceRow(
                    icon: "bolt.slash",
                    title: "No live filtering",
                    detail: "Rules currently evaluate normalized case events, not the live stream.",
                    status: "Not implemented",
                    tone: .warning
                )
            }

            CommandLine(command: "rootstock-blue detect run --ruleset samples --case ./demo.rsbcase")
        }
    }
}
