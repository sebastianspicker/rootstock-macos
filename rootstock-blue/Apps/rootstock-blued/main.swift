import Foundation
import RootstockBlueXPC
import RootstockBlueESKit
import RootstockBlueCore

/// Non-installing LaunchDaemon entry point that exercises the ES client boundary.
/// Does not depend on RootstockBlueFX.
@main
struct RootstockBlued {
    static func main() {
        fputs("rootstock-blued: daemon is not installed\n", stderr)
        let client = LiveESClientFactory.make()
        let profile = ESSubscriptionProfile.builtin(.quiet)
        do {
            try client.start(profile: profile)
            let counters = client.counters
            print("status=running profile=quiet received=\(counters.received)")
            client.stop()
            exit(0)
        } catch {
            fputs("error: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}
