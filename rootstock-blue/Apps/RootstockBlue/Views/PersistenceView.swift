import SwiftUI

struct PersistenceView: View {
    private let surfaces = [
        ("bolt.horizontal", "Launch agents", "Per-user launchd persistence"),
        ("gearshape.2", "Launch daemons", "System launchd persistence"),
        ("person.crop.circle.badge.checkmark", "Login items and BTM", "Background-task registration"),
        ("clock.arrow.circlepath", "Cron and at", "Scheduled command execution"),
    ]

    var body: some View {
        WorkspacePage(
            eyebrow: "Persistence inventory",
            title: "Autostart surfaces",
            summary: "Review supported launch, login, and scheduled-execution evidence without collapsing collection gaps into clean results."
        ) {
            InstrumentSection("Inventory", detail: "No case loaded") {
                ForEach(surfaces, id: \.1) { surface in
                    EvidenceRow(
                        icon: surface.0,
                        title: surface.1,
                        detail: surface.2,
                        status: "Not loaded"
                    )
                }
            }

            EmptyEvidenceView(
                title: "No persistence evidence",
                description: "Parse a supported source or run a persistence collection pack to populate this inventory.",
                systemImage: "bolt.horizontal.circle"
            )
        }
    }
}
