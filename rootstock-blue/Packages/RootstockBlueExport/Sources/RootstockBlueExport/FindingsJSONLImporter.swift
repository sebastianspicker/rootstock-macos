import Foundation
import RootstockBlueCase
import RootstockBlueCore

/// Import rootstock-red findings JSONL (one Finding JSON object per line) into a blue case.
///
/// Family bridge (DD-011). Maps red `Finding` shape loosely without linking RootstockCore.
public enum FindingsJSONLImporter: Sendable {
    @discardableResult
    public static func importIntoCase(findingsURL: URL, casePackage: CasePackage) throws -> Int {
        var events: [EventEnvelope] = []
        try JSONLRecordReader.forEachRecord(contentsOf: findingsURL) { record in
            let text = try JSONLRecordReader.strictUTF8(record)
                .trimmingCharacters(in: .whitespaces)
            guard !text.isEmpty else { return }
            let data = Data(text.utf8)
            guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw RootstockBlueError.io("finding JSONL line is not an object")
            }
            let id = obj["id"] as? String ?? UUID().uuidString
            let title = obj["title"] as? String ?? id
            let severity = obj["severity"] as? String ?? "info"
            let category = obj["category"] as? String ?? "other"
            let confidence = obj["confidence"] as? String ?? "medium"
            let event = EventEnvelope(
                identity: .init(kind: "finding.import", label: "rootstock-red"),
                capture: .init(source: .parser),
                payload: .init(entityRefs: [
                    EntityID(kind: .auth, value: "finding:\(id)"),
                ],
                properties: [
                    "finding.id": id,
                    "finding.title": title,
                    "finding.severity": severity,
                    "finding.category": category,
                    "finding.confidence": confidence,
                    "family.source": "rootstock-red",
                    FieldTaxonomy.eventType: "finding.import",
                ], provenance: findingsURL.lastPathComponent,
                confidence: 0.85
                )
            )
            events.append(event)
        }
        try casePackage.appendEventBatch(
            events,
            stream: "es",
            custody: CustodyEvent(
                actor: "rootstock-blue",
                action: "import.findings_jsonl",
                detail: "Imported \(events.count) findings from \(findingsURL.lastPathComponent)"
            )
        )
        return events.count
    }
}
