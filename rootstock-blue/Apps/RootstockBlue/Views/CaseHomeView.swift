import SwiftUI

struct CaseHomeView: View {
    var body: some View {
        WorkspacePage(
            eyebrow: "Case workspace",
            title: "Case package",
            summary: "Open or create a local .rsbcase package. Events, artifacts, and custody records stay together in one reviewable boundary."
        ) {
            EmptyEvidenceView(
                title: "No case open",
                description: "Create a case with the CLI, then open it here when native case loading is available.",
                systemImage: "folder.badge.questionmark"
            )

            InstrumentSection("Case workflow", detail: "SQLite · JSONL · custody") {
                EvidenceRow(
                    icon: "1.circle",
                    title: "Create the case boundary",
                    detail: "Establishes the package and initial custody record.",
                    status: "Required",
                    tone: .accent
                )
                EvidenceRow(
                    icon: "2.circle",
                    title: "Parse or collect evidence",
                    detail: "Normalizes supported artifacts into the case timeline.",
                    status: "Local"
                )
                EvidenceRow(
                    icon: "3.circle",
                    title: "Verify custody",
                    detail: "Recomputes recorded hashes before review or export.",
                    status: "Verify",
                    tone: .verified
                )
            }

            CommandLine(command: "rootstock-blue case create ./demo.rsbcase --name demo")
        }
    }
}
