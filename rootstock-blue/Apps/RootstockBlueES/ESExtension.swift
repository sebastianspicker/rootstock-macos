import Foundation
import RootstockBlueCore
import RootstockBlueESKit

/// Endpoint Security System Extension entry with one client per process.
/// Thin callbacks only; no FX, no Case SQLite, no GUI.
///
/// Production requires:
/// - `com.apple.developer.endpoint-security.client` (Apple program)
/// - Full Disk Access
/// - System Extension approval (MDM for fleet)
///
/// AUTH/block mode is not implemented.
@main
struct RootstockBlueESExtension {
    static func main() {
        // The current factory returns the mock client because no live entitlement is bundled.
        let client = LiveESClientFactory.make(preferLive: false)
        let profile = ESSubscriptionProfile.builtin(.ir)
        do {
            try client.start(profile: profile)
            fputs("RootstockBlueES: mock ES client started (monitor only)\n", stderr)
        } catch {
            fputs("RootstockBlueES: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
        // The source-only target exits after a bounded mock session.
        RunLoop.main.run(until: Date().addingTimeInterval(0.1))
        client.stop()
    }
}
