import Foundation
import RootstockCore

/// Optional C2 transport abstraction (not linked into default assess CLI).
public protocol Transport: Sendable {
    static var id: String { get }
    func connect() async throws
    func send(_ data: Data) async throws
    func receive() async throws -> Data
    func close() async
}

/// Nonfunctional HTTPS transport contract. It opens no listeners or connections.
public struct HTTPTransport: Transport {
    public static let id = "transport.https"
    public var endpoint: URL

    public init(endpoint: URL) {
        self.endpoint = endpoint
    }

    public func connect() async throws {
        throw RootstockError.invalidArgument("HTTPTransport is disabled")
    }

    public func send(_ data: Data) async throws {
        throw RootstockError.invalidArgument("HTTPTransport is disabled")
    }

    public func receive() async throws -> Data {
        throw RootstockError.invalidArgument("HTTPTransport is disabled")
    }

    public func close() async {}
}
