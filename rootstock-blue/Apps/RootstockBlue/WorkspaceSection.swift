import SwiftUI

enum WorkspaceSection: String, CaseIterable, Identifiable {
    case caseHome
    case live
    case timeline
    case persistence
    case collect
    case detections
    case research

    var id: String { rawValue }

    var title: String {
        switch self {
        case .caseHome: return "Case"
        case .live: return "Live monitor"
        case .timeline: return "Timeline"
        case .persistence: return "Persistence"
        case .collect: return "Collect"
        case .detections: return "Detections"
        case .research: return "Research"
        }
    }

    var detail: String {
        switch self {
        case .caseHome: return "Package and custody"
        case .live: return "Monitor-only ES"
        case .timeline: return "Normalized events"
        case .persistence: return "Autostart surfaces"
        case .collect: return "Bounded artifact packs"
        case .detections: return "Fixture-backed rules"
        case .research: return "Session recording"
        }
    }

    var systemImage: String {
        switch self {
        case .caseHome: return "folder"
        case .live: return "waveform.path.ecg"
        case .timeline: return "timeline.selection"
        case .persistence: return "bolt.horizontal"
        case .collect: return "tray.and.arrow.down"
        case .detections: return "shield.lefthalf.filled"
        case .research: return "flask"
        }
    }
}
