import Foundation
import RootstockBlueCore

/// USB device connection history from fixture JSON / JSONL exports.
///
/// Surfaces vendor/product IDs, serials, product names, and connection times
/// for removable-media and HID-injection IR hunting.
/// Offline-only - does not query live IOKit.
public struct USBHistoryParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "USBHISTORY",
        tier: .tier2,
        description: "USB device connection history (VID/PID/serial/product)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var seen = PathDeduper()
        var events = fixtureEvents(root: root, seen: &seen)
        for url in root.enumerate(matching: isUSBInventoryFile) where seen.insert(url) {
            events.append(contentsOf: parseFile(at: url))
        }
        return events
    }

    private func fixtureEvents(root: ArtifactRoot, seen: inout PathDeduper) -> [EventEnvelope] {
        let paths = ["Library/Preferences/usb_history.json", "Library/Logs/usb_devices.jsonl", "Library/Preferences/com.apple.iokit.usb.json"]
        var events: [EventEnvelope] = []
        for path in paths {
            if let url = root.firstExisting([path]), seen.insert(url) { events.append(contentsOf: parseFile(at: url)) }
        }
        return events
    }

    private func isUSBInventoryFile(_ url: URL) -> Bool {
        let name = url.lastPathComponent
        if ["usb_history.json", "usb_devices.jsonl", "usb_devices.json", "com.apple.iokit.usb.json"].contains(name) { return true }
        return url.path.contains("iokit") && name.hasSuffix(".json") && url.path.lowercased().contains("usb")
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" || url.lastPathComponent.hasSuffix(".jsonl") {
            return ArtifactIO.jsonlDictionaries(contentsOf: url).compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        return parseJSON(at: url)
    }

    private func parseJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries = ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["devices", "history", "items", "usb"],
            identityKeys: ["vendor_id", "product_id", "serial"]
        )
        return entries.compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private struct USBDetails {
        let vendorID: String
        let productID: String
        let serial: String
        let productName: String
        let connectedAt: String
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        guard let details = usbDetails(from: item) else { return nil }
        let risk = usbRiskTags(item: item, productName: details.productName, vendorID: details.vendorID)
        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "device.usb",
                label: "USBHISTORY"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["connected_at"] ?? item["timestamp"] ?? item["time"]) ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .host, value: "usb|\(details.vendorID)|\(details.productID)|\(details.serial)")],
                properties: usbFields(item: item, details: details, risk: risk),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.9
            )
        )
    }

    private func usbDetails(from item: [String: Any]) -> USBDetails? {
        let vendorID = stringish(item["vendor_id"]) ?? stringish(item["vid"]) ?? stringish(item["idVendor"]) ?? ""
        let productID = stringish(item["product_id"]) ?? stringish(item["pid"]) ?? stringish(item["idProduct"]) ?? ""
        let serial = stringish(item["serial"]) ?? stringish(item["serial_number"]) ?? stringish(item["USBSerialNumber"]) ?? ""
        let productName = stringish(item["product_name"]) ?? stringish(item["product"]) ?? stringish(item["name"]) ?? stringish(item["USBProductName"]) ?? ""
        guard !vendorID.isEmpty || !productID.isEmpty || !serial.isEmpty || !productName.isEmpty else { return nil }
        return USBDetails(vendorID: vendorID, productID: productID, serial: serial, productName: productName, connectedAt: stringish(item["connected_at"]) ?? stringish(item["timestamp"]) ?? stringish(item["time"]) ?? stringish(item["first_seen"]) ?? "")
    }

    private func usbRiskTags(item: [String: Any], productName: String, vendorID: String) -> [String] {
        var tags = (stringish(item["risk_tags"]) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let name = productName.lowercased()
        let vendor = vendorID.lowercased()
        let deviceClass = (stringish(item["device_class"]) ?? stringish(item["class"]) ?? stringish(item["usb_class"]) ?? "").lowercased()
        if isMassStorage(item: item, deviceClass: deviceClass, name: name) { appendRiskTags(["mass_storage"], to: &tags) }
        if isHIDInjector(item: item, deviceClass: deviceClass, name: name) { appendRiskTags(["hid_inject"], to: &tags) }
        if isUnknownVendor(item: item, vendor: vendor, name: name) { appendRiskTags(["unknown_vendor"], to: &tags) }
        return tags
    }

    private func isMassStorage(item: [String: Any], deviceClass: String, name: String) -> Bool {
        ["mass", "storage"].contains(where: deviceClass.contains) || deviceClass == "08" || ["mass storage", "usb drive", "flash"].contains(where: name.contains) || boolish(item["mass_storage"]) == true
    }

    private func isHIDInjector(item: [String: Any], deviceClass: String, name: String) -> Bool {
        deviceClass.contains("hid") || ["hid inject", "rubber ducky", "badusb", "inject"].contains(where: name.contains) || boolish(item["hid_inject"]) == true
    }

    private func isUnknownVendor(item: [String: Any], vendor: String, name: String) -> Bool {
        name.contains("evil") || vendor.contains("evil") || ["ffff", "0000"].contains(vendor) || boolish(item["unknown_vendor"]) == true
    }

    private func usbFields(item: [String: Any], details: USBDetails, risk: [String]) -> [String: String] {
        var fields = [
            "usb.vendor_id": details.vendorID, "usb.product_id": details.productID,
            "usb.serial": details.serial, "usb.product_name": details.productName,
            "usb.connected_at": details.connectedAt, FieldTaxonomy.eventType: "device.usb",
        ]
        if !risk.isEmpty { fields["usb.risk_tags"] = risk.joined(separator: ",") }
        if let manufacturer = stringish(item["manufacturer"]) ?? stringish(item["vendor_name"]) { fields["usb.manufacturer"] = manufacturer }
        return fields
    }

    private func appendRiskTags(_ additions: [String], to tags: inout [String]) {
        for tag in additions where !tags.contains(tag) { tags.append(tag) }
    }
}
