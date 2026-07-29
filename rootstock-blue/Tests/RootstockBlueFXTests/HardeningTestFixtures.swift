@testable import RootstockBlueCore

enum HardeningTestFixtures {
    struct Plane {
        let plugin: String
        let eventType: String
        let fieldPrefix: String
        let fileName: String
        let name: String
        let riskTag: String
    }

    static func event(_ plugin: String, _ type: String, _ fields: [String: String]) -> EventEnvelope {
        EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: type,
                label: plugin
            ),
            capture: EventEnvelope.Capture(
                source: .parser
            ),
            payload: EventEnvelope.Payload(
                properties: fields
            )
        )
    }

    static func planeEvents(wave: String, specifications: [Plane]) -> [EventEnvelope] {
        specifications.map { specification in
            event(
                specification.plugin,
                specification.eventType,
                [
                    "\(specification.fieldPrefix).path": "/Users/alice/Library/Preferences/\(specification.fileName)",
                    "\(specification.fieldPrefix).name": specification.name,
                    "\(specification.fieldPrefix).risk_tags": "\(specification.riskTag),\(wave)",
                    "\(specification.fieldPrefix).secrets_exported": "false",
                ]
            )
        }
    }
}
