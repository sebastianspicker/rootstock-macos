import SwiftUI
import RootstockBlueCore

@main
struct RootstockBlueApp: App {
    @State private var mode: ProductMode = .liveIR

    var body: some Scene {
        WindowGroup {
            ContentView(mode: $mode)
                .frame(minWidth: 980, minHeight: 640)
        }
        .defaultSize(width: 1180, height: 760)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}
