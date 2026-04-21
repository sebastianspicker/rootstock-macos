import XCTest
@testable import PhysicalSecurity
@testable import Models

final class PhysicalSecurityTests: XCTestCase {

    // MARK: - BluetoothDevice model tests

    func testBluetoothDeviceNodeType() {
        let device = BluetoothDevice(name: "Magic Keyboard", address: "AA:BB:CC:DD:EE:FF", deviceType: "Keyboard", connected: true)
        XCTAssertEqual(device.nodeType, "BluetoothDevice")
    }

    func testBluetoothDeviceJSONRoundTrip() throws {
        let device = BluetoothDevice(name: "AirPods Pro", address: "11:22:33:44:55:66", deviceType: "Headphones", connected: false)
        let data = try JSONEncoder().encode(device)
        let decoded = try JSONDecoder().decode(BluetoothDevice.self, from: data)
        XCTAssertEqual(decoded.name, "AirPods Pro")
        XCTAssertEqual(decoded.address, "11:22:33:44:55:66")
        XCTAssertEqual(decoded.deviceType, "Headphones")
        XCTAssertFalse(decoded.connected)
    }

    func testBluetoothDeviceSnakeCaseEncoding() throws {
        let device = BluetoothDevice(name: "Mouse", address: "AA:BB:CC:DD:EE:FF", deviceType: "Mouse", connected: true)
        let data = try JSONEncoder().encode(device)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertNotNil(json["device_type"])
        XCTAssertNil(json["deviceType"])
    }

    // MARK: - Bluetooth JSON parsing

    func testParseBluetoothJSON() {
        let ds = PhysicalSecurityDataSource()
        let json: [String: Any] = [
            "SPBluetoothDataType": [
                [
                    "controller_properties": [
                        "controller_state": "attrib_on",
                        "controller_discoverable": "attrib_off"
                    ],
                    "device_connected": [
                        ["Magic Keyboard": [
                            "device_address": "AA:BB:CC:DD:EE:FF",
                            "device_minorType": "Keyboard"
                        ]]
                    ],
                    "device_not_connected": [
                        ["AirPods": [
                            "device_address": "11:22:33:44:55:66",
                            "device_minorType": "Headphones"
                        ]]
                    ]
                ]
            ]
        ]

        let (devices, enabled, discoverable, errors) = ds.parseBluetoothJSON(json)
        XCTAssertEqual(devices.count, 2)
        XCTAssertEqual(enabled, true)
        XCTAssertEqual(discoverable, false)
        XCTAssertTrue(errors.isEmpty)

        let keyboard = devices.first { $0.name == "Magic Keyboard" }
        XCTAssertNotNil(keyboard)
        XCTAssertEqual(keyboard?.address, "AA:BB:CC:DD:EE:FF")
        XCTAssertEqual(keyboard?.deviceType, "Keyboard")
        XCTAssertTrue(keyboard?.connected ?? false)

        let airpods = devices.first { $0.name == "AirPods" }
        XCTAssertNotNil(airpods)
        XCTAssertFalse(airpods?.connected ?? true)
    }

    func testParseBluetoothJSONEmpty() {
        let ds = PhysicalSecurityDataSource()
        let json: [String: Any] = ["SPBluetoothDataType": [[:] as [String: Any]]]
        let (devices, enabled, discoverable, errors) = ds.parseBluetoothJSON(json)
        XCTAssertTrue(devices.isEmpty)
        XCTAssertNil(enabled)
        XCTAssertNil(discoverable)
        XCTAssertTrue(errors.isEmpty)
    }

    // MARK: - Display sleep parsing

    func testParseDisplaySleep() {
        let ds = PhysicalSecurityDataSource()
        let output = """
        Battery Power:
         displaysleep         10
         disksleep            10
         sleep                1
        AC Power:
         displaysleep         15
         disksleep            10
         sleep                0
        """
        // Should pick the first occurrence
        let result = ds.parseDisplaySleep(output)
        XCTAssertEqual(result, 10)
    }

    func testParseDisplaySleepMissing() {
        let ds = PhysicalSecurityDataSource()
        let result = ds.parseDisplaySleep("no relevant output here")
        XCTAssertNil(result)
    }

    // MARK: - Secure boot parsing

    func testParseSecureBootExternalBootAllowed() {
        let ds = PhysicalSecurityDataSource()
        let output = """
        Security Mode: Full Security
        External Boot: external boot allowed
        """
        let (level, externalBoot) = ds.parseSecureBootOutput(output)
        XCTAssertEqual(level, "full")
        XCTAssertEqual(externalBoot, true)
    }

    func testParseSecureBootExternalBootNotAllowed() {
        let ds = PhysicalSecurityDataSource()
        let output = """
        Security Mode: Full Security
        External Boot: external boot not allowed
        """
        let (level, externalBoot) = ds.parseSecureBootOutput(output)
        XCTAssertEqual(level, "full")
        XCTAssertEqual(externalBoot, false)
    }

    func testParseSecureBootExternalBootDisallowed() {
        let ds = PhysicalSecurityDataSource()
        let output = """
        Reduced Security
        external boot disallowed
        """
        let (level, externalBoot) = ds.parseSecureBootOutput(output)
        XCTAssertEqual(level, "reduced")
        XCTAssertEqual(externalBoot, false)
    }

    func testParseSecureBootNoExternalBootLine() {
        let ds = PhysicalSecurityDataSource()
        let output = "Full Security"
        let (level, externalBoot) = ds.parseSecureBootOutput(output)
        XCTAssertEqual(level, "full")
        XCTAssertNil(externalBoot)
    }

    func testParseSecureBootEmpty() {
        let ds = PhysicalSecurityDataSource()
        let (level, externalBoot) = ds.parseSecureBootOutput("")
        XCTAssertNil(level)
        XCTAssertNil(externalBoot)
    }

    // MARK: - DataSource metadata

    func testPhysicalSecurityDataSourceMetadata() {
        let ds = PhysicalSecurityDataSource()
        XCTAssertEqual(ds.name, "Physical Security")
        XCTAssertFalse(ds.requiresElevation)
    }

    // MARK: - Collect without crash

    func testCollectWithoutCrash() async {
        let ds = PhysicalSecurityDataSource()
        let result = await ds.collectAll()
        // On CI, BT may not be available — just verify it doesn't crash
        // and returns a valid result structure
        XCTAssertNotNil(result)
        XCTAssertTrue(result.bluetoothDevices is [BluetoothDevice])
    }
}
