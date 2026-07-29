import Foundation
import RootstockBlueCase
import RootstockBlueCore

/// Import rootstock-red findings JSONL (one Finding JSON object per line) into a blue case.
///
/// Family bridge (DD-011). Maps red `Finding` shape loosely without linking RootstockCore.
public enum FindingsJSONLImporter: Sendable {
    @discardableResult
    public static func importIntoCase(findingsURL: URL, casePackage: CasePackage) throws -> Int {
        let text = try String(contentsOf: findingsURL, encoding: .utf8)
        var count = 0
        for line in text.split(whereSeparator: \.isNewline) {
            let s = String(line).trimmingCharacters(in: .whitespaces)
            guard !s.isEmpty, let data = s.data(using: .utf8) else { continue }
            guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                continue
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
            try casePackage.appendEventJSONL(event, stream: "es")
            try casePackage.insertTimelineEvent(event)
            count += 1
        }
        try casePackage.appendCustody(
            CustodyEvent(
                actor: "rootstock-blue",
                action: "import.findings_jsonl",
                detail: "Imported \(count) findings from \(findingsURL.lastPathComponent)"
            )
        )
        try casePackage.updateHashes()
        return count
    }
}
