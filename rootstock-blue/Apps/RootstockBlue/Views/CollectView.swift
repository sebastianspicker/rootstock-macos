import SwiftUI

struct CollectView: View {
    var body: some View {
        WorkspacePage(
            eyebrow: "Bounded acquisition",
            title: "Collection packs",
            summary: "Choose an explicit source tree and a bounded pack. Preflight reports Full Disk Access and system-extension requirements before collection."
        ) {
            InstrumentSection("Available packs", detail: "Offline-safe defaults") {
                EvidenceRow(
                    icon: "tray",
                    title: "triage-lite",
                    detail: "Fast host and incident context with a limited artifact footprint.",
                    status: "Available",
                    tone: .verified
                )
                EvidenceRow(
                    icon: "bolt",
                    title: "persistence",
                    detail: "Launchd, login, scheduled-task, and related autostart sources.",
                    status: "Available",
                    tone: .verified
                )
                EvidenceRow(
                    icon: "globe",
                    title: "browser",
                    detail: "Supported browser history and download metadata.",
                    status: "Sensitive",
                    tone: .warning
                )
                EvidenceRow(
                    icon: "doc.text.magnifyingglass",
                    title: "logs",
                    detail: "Selected log sources for timeline enrichment.",
                    status: "FDA may apply",
                    tone: .warning
                )
            }

            InstrumentSection("Preflight") {
                EvidenceRow(
                    icon: "folder.badge.questionmark",
                    title: "Source tree",
                    detail: "Collection does not start without an explicit source.",
                    status: "Not selected",
                    tone: .warning
                )
                EvidenceRow(
                    icon: "lock.shield",
                    title: "Case destination",
                    detail: "Existing case paths are not overwritten.",
                    status: "Protected",
                    tone: .verified
                )
            }

            CommandLine(command: "rootstock-blue collect triage-lite --case ./demo.rsbcase --source ./image --offline")
        }
    }
}
