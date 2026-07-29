import SwiftUI
import RootstockBlueCore

struct LiveMonitorView: View {
    var body: some View {
        WorkspacePage(
            eyebrow: "Live IR",
            title: "Endpoint Security monitor",
            summary: "Monitor-only Endpoint Security visibility with explicit loss accounting. Blocking and AUTH decisions remain off by default."
        ) {
            MetricStrip(metrics: [
                WorkspaceMetric(label: "Received", value: "0", tone: .neutral),
                WorkspaceMetric(label: "Enqueued", value: "0", tone: .neutral),
                WorkspaceMetric(label: "Dropped", value: "0", tone: .verified),
                WorkspaceMetric(label: "Mapped", value: "0", tone: .neutral),
            ])

            InstrumentSection("Stream state", detail: "No active session") {
                EmptyEvidenceView(
                    title: "No events received",
                    description: "Start an approved monitor session to populate the process and event stream.",
                    systemImage: "waveform.path.ecg"
                )
            }

            InstrumentSection("Operating boundary") {
                EvidenceRow(
                    icon: "eye",
                    title: "Monitor only",
                    detail: "The default profile observes events and does not authorize or block them.",
                    status: "Enforced",
                    tone: .verified
                )
                EvidenceRow(
                    icon: "exclamationmark.triangle",
                    title: "Loss is visible",
                    detail: "Queue drops are counted rather than silently discarded.",
                    status: "0 dropped",
                    tone: .verified
                )
                EvidenceRow(
                    icon: "checkmark.seal",
                    title: "System approval required",
                    detail: "Live ES requires signing, entitlements, and user or MDM approval.",
                    status: "External",
                    tone: .warning
                )
            }
        }
    }
}
