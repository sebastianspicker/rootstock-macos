import Foundation
import RootstockBlueXPC
import RootstockBlueCore

/// Non-installing entry point for the allowlisted XPC helper contract.
@main
struct RootstockBlueHelper {
    static func main() {
        fputs("RootstockBlueHelper: no privileged installation performed\n", stderr)
        let stub = LocalXPCStub()
        Task {
            let response = try await stub.handle(
                XPCRequest(capability: .getAgentStatus)
            )
            print(response.message)
            exit(response.ok ? 0 : 1)
        }
        RunLoop.main.run(until: Date().addingTimeInterval(1))
    }
}
