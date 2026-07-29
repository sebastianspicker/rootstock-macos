import SwiftUI
import RootstockBlueCore

enum RootstockTone {
    case accent
    case critical
    case warning
    case verified
    case neutral

    var color: Color {
        switch self {
        case .accent: return .accentColor
        case .critical: return .red
        case .warning: return .orange
        case .verified: return .green
        case .neutral: return .secondary
        }
    }
}

struct WorkspacePage<Content: View>: View {
    let eyebrow: String
    let title: String
    let summary: String
    @ViewBuilder let content: Content

    init(
        eyebrow: String,
        title: String,
        summary: String,
        @ViewBuilder content: () -> Content
    ) {
        self.eyebrow = eyebrow
        self.title = title
        self.summary = summary
        self.content = content()
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(eyebrow.uppercased())
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .tracking(1.2)
                        .foregroundStyle(.secondary)
                    Text(title)
                        .font(.system(size: 34, weight: .semibold, design: .default))
                        .tracking(-0.7)
                    Text(summary)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: 680, alignment: .leading)
                }
                Divider()
                content
                ProvenanceRail()
            }
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .background(.background)
    }
}

struct InstrumentSection<Content: View>: View {
    let title: String
    let detail: String?
    @ViewBuilder let content: Content

    init(_ title: String, detail: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.detail = detail
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .firstTextBaseline) {
                Text(title)
                    .font(.headline)
                Spacer()
                if let detail {
                    Text(detail)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
            Divider()
            content
        }
    }
}

struct StatusLabel: View {
    let text: String
    let tone: RootstockTone

    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 10, weight: .bold, design: .monospaced))
            .tracking(0.5)
            .foregroundStyle(tone.color)
            .padding(.horizontal, 7)
            .padding(.vertical, 4)
            .overlay {
                RoundedRectangle(cornerRadius: 3)
                    .stroke(tone.color.opacity(0.75), lineWidth: 1)
            }
            .accessibilityLabel(text)
    }
}

struct WorkspaceMetric {
    let label: String
    let value: String
    let tone: RootstockTone
}

struct MetricStrip: View {
    let metrics: [WorkspaceMetric]

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(metrics.enumerated()), id: \.offset) { index, metric in
                VStack(alignment: .leading, spacing: 6) {
                    Text(metric.value)
                        .font(.title2.monospacedDigit().weight(.semibold))
                        .foregroundStyle(metric.tone.color)
                    Text(metric.label.uppercased())
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 14)
                .padding(.vertical, 12)

                if index < metrics.count - 1 {
                    Divider()
                }
            }
        }
        .overlay {
            RoundedRectangle(cornerRadius: 4)
                .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
        }
    }
}

struct EvidenceRow: View {
    let icon: String
    let title: String
    let detail: String
    let status: String
    var tone: RootstockTone = .neutral

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(tone.color)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .fontWeight(.medium)
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 16)
            Text(status)
                .font(.caption.monospaced())
                .foregroundStyle(tone.color)
        }
        .padding(.vertical, 9)
        .overlay(alignment: .bottom) { Divider() }
    }
}

struct CommandLine: View {
    let command: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text("CLI")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundStyle(.secondary)
            Text(command)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(12)
        .background(.quaternary.opacity(0.35))
        .overlay {
            RoundedRectangle(cornerRadius: 4)
                .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
        }
    }
}

struct EmptyEvidenceView: View {
    let title: String
    let description: String
    let systemImage: String

    var body: some View {
        ContentUnavailableView(
            title,
            systemImage: systemImage,
            description: Text(description)
        )
        .frame(maxWidth: .infinity, minHeight: 180)
        .overlay {
            RoundedRectangle(cornerRadius: 4)
                .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
        }
    }
}

struct ProvenanceRail: View {
    private let stages = ["Collected", "Imported", "Derived", "Case"]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()
            HStack(spacing: 0) {
                ForEach(Array(stages.enumerated()), id: \.offset) { index, stage in
                    HStack(spacing: 8) {
                        Text(String(index + 1))
                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                            .foregroundStyle(index == stages.count - 1 ? Color.accentColor : Color.secondary)
                            .frame(width: 18, height: 18)
                            .overlay {
                                Circle()
                                    .stroke(index == stages.count - 1 ? Color.accentColor : Color.secondary, lineWidth: 1)
                            }
                        Text(stage)
                            .font(.caption.weight(.medium))
                        if index < stages.count - 1 {
                            Rectangle()
                                .fill(Color.secondary.opacity(0.25))
                                .frame(height: 1)
                                .padding(.horizontal, 10)
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
            }
            .accessibilityElement(children: .combine)
            Text("Provenance appears when a case or collection is loaded.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 14)
    }
}

struct WorkspaceStatusBar: View {
    let mode: ProductMode

    var body: some View {
        HStack(spacing: 12) {
            StatusLabel(text: mode.bannerTitle, tone: tone)
            Text("Monitor-only ES · local-first DFIR")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
            Label("Local case boundary", systemImage: "lock")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 18)
        .frame(height: 42)
        .background(Color.secondary.opacity(0.06))
    }

    private var tone: RootstockTone {
        switch mode {
        case .liveIR: return .warning
        case .deadBox: return .accent
        case .research: return .neutral
        }
    }
}
