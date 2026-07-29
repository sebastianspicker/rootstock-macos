import Foundation
import RootstockBlueCore

/// Typed XPC surface used by the local stub and source-only app and daemon targets.
public protocol RootstockBlueXPCServicing: Sendable {
    func handle(_ request: XPCRequest) async throws -> XPCResponse
}

/// Local in-process stub for CLI/tests (no privileged elevation).
public struct LocalXPCStub: RootstockBlueXPCServicing {
    public init() {}

    public func handle(_ request: XPCRequest) async throws -> XPCResponse {
        if XPCCapability.forbidden.contains(request.capability.rawValue) {
            throw RootstockBlueError.xpcDenied(request.capability.rawValue)
        }
        return response(for: request)
    }

    private func response(for request: XPCRequest) -> XPCResponse {
        switch request.capability {
        case .getAgentStatus:
            return XPCResponse(id: request.id, ok: true, message: "stub: agent not installed")
        case .startESProfile:
            return profileResponse(for: request)
        case .stopES:
            return XPCResponse(id: request.id, ok: true, message: "stub: would stop ES")
        case .collectPack:
            return collectionResponse(for: request)
        case .exportCase:
            return exportResponse(for: request)
        case .getLossCounters:
            return XPCResponse(id: request.id, ok: true, message: "ok", lossCounters: LossCounters())
        }
    }

    private func profileResponse(for request: XPCRequest) -> XPCResponse {
        let profile = request.profile ?? "ir"
        return XPCResponse(id: request.id, ok: true, message: "stub: would start ES profile \(profile) (monitor only)")
    }

    private func collectionResponse(for request: XPCRequest) -> XPCResponse {
        XPCResponse(id: request.id, ok: true, message: "stub: collect \(request.packName ?? "?")")
    }

    private func exportResponse(for request: XPCRequest) -> XPCResponse {
        XPCResponse(id: request.id, ok: true, message: "stub: export \(request.exportPath ?? "?")")
    }
}
