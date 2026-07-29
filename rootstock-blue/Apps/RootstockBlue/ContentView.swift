import SwiftUI
import RootstockBlueCore

struct ContentView: View {
    @Binding var mode: ProductMode
    @SceneStorage("rootstock-blue.selection") private var storedSelection = WorkspaceSection.caseHome.rawValue

    var body: some View {
        NavigationSplitView {
            List(selection: selection) {
                Section("Investigation") {
                    ForEach(WorkspaceSection.allCases) { section in
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(section.title)
                                Text(section.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: section.systemImage)
                                .foregroundStyle(.secondary)
                        }
                        .tag(section)
                    }
                }
            }
            .listStyle(.sidebar)
            .navigationTitle("Rootstock Blue")
            .navigationSplitViewColumnWidth(min: 190, ideal: 220, max: 280)
        } detail: {
            VStack(spacing: 0) {
                WorkspaceStatusBar(mode: mode)
                Divider()
                selectedView
            }
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    Picker("Mode", selection: $mode) {
                        ForEach(ProductMode.allCases, id: \.self) { productMode in
                            Text(productMode.bannerTitle).tag(productMode)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 360)
                }
            }
        }
        .navigationSplitViewStyle(.balanced)
    }

    private var selection: Binding<WorkspaceSection?> {
        Binding {
            WorkspaceSection(rawValue: storedSelection) ?? .caseHome
        } set: { next in
            storedSelection = (next ?? .caseHome).rawValue
        }
    }

    @ViewBuilder
    private var selectedView: some View {
        switch WorkspaceSection(rawValue: storedSelection) ?? .caseHome {
        case .caseHome:
            CaseHomeView()
        case .live:
            LiveMonitorView()
        case .timeline:
            CaseTimelineView()
        case .persistence:
            PersistenceView()
        case .collect:
            CollectView()
        case .detections:
            DetectionsView()
        case .research:
            ResearchView()
        }
    }
}
