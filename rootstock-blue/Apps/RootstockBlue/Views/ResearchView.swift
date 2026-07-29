import SwiftUI

struct ResearchView: View {
    var body: some View {
        WorkspacePage(
            eyebrow: "Detection engineering",
            title: "Research sessions",
            summary: "Record a bounded ES profile into a case package, then convert reviewed events into deterministic detection fixtures."
        ) {
            InstrumentSection("Session pipeline", detail: "Profile → case → fixture") {
                EvidenceRow(
                    icon: "waveform",
                    title: "Record",
                    detail: "Capture the selected Endpoint Security profile with explicit loss counters.",
                    status: "Profiled",
                    tone: .accent
                )
                EvidenceRow(
                    icon: "shippingbox",
                    title: "Preserve",
                    detail: "Store events and custody records inside a local case package.",
                    status: "Local",
                    tone: .verified
                )
                EvidenceRow(
                    icon: "checklist",
                    title: "Promote",
                    detail: "Review and minimize captured events before fixture use.",
                    status: "Manual"
                )
            }

            InstrumentSection("Isolation boundary") {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                    VStack(alignment: .leading, spacing: 5) {
                        Text("Use dedicated bare metal for hostile samples")
                            .fontWeight(.semibold)
                        Text("UTM guests are not treated as a hermetic analysis boundary.")
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(14)
                .overlay {
                    RoundedRectangle(cornerRadius: 4)
                        .stroke(Color.orange.opacity(0.7), lineWidth: 1)
                }
            }

            EmptyEvidenceView(
                title: "No research session",
                description: "Start a controlled recorder session to create case-backed fixture evidence.",
                systemImage: "flask"
            )
        }
    }
}
