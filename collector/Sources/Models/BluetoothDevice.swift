import Foundation

/// A paired Bluetooth device discovered on the host.
public struct BluetoothDevice: Codable, Sendable, GraphNode {
    public let name: String
    public let address: String
    public let deviceType: String
    public let connected: Bool

    public var nodeType: String { "BluetoothDevice" }

    public init(name: String, address: String, deviceType: String, connected: Bool) {
        self.name = name
        self.address = address
        self.deviceType = deviceType
        self.connected = connected
    }

    enum CodingKeys: String, CodingKey {
        case name
        case address
        case deviceType = "device_type"
        case connected
    }
}
