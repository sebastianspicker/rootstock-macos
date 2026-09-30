import Foundation
import RootstockBlueCore

/// CUPS / print job history inventory for sensitive-document leakage IR.
///
/// Emits job_id, document name, user, printer, and risk tags - not full
/// spool binary dumps.
public struct PrintJobsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "PRINTJOBS",
        tier: .tier2,
        description: "CUPS print job history with sensitive-document risk tags"
    )

    private struct PrintJobDetails {
        let jobID: String
        let document: String
        let user: String
        let printer: String
        let pages: String
    }

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/print_jobs.json",
            "Library/Preferences/cups_jobs.json",
            "Library/Logs/print_jobs.jsonl",
            "var/spool/cups/jobs.json",
            "private/var/spool/cups/jobs.json",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "print_jobs.json"
                || name == "cups_jobs.json"
                || name == "print_jobs.jsonl"
                || name == "jobs.json"
        }) where seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["jobs", "items"],
            identityKeys: ["job_id", "document"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let details = PrintJobDetails(
            jobID: stringish(item["job_id"]) ?? stringish(item["id"]) ?? stringish(item["job-id"]) ?? "",
            document: stringish(item["document"]) ?? stringish(item["title"])
                ?? stringish(item["job-name"]) ?? stringish(item["name"]) ?? "",
            user: stringish(item["user"]) ?? stringish(item["job-originating-user-name"]) ?? "",
            printer: stringish(item["printer"]) ?? stringish(item["printer-name"])
                ?? stringish(item["queue"]) ?? "",
            pages: stringish(item["pages"]) ?? stringish(item["job-media-sheets"]) ?? ""
        )
        guard !details.document.isEmpty || !details.jobID.isEmpty else { return nil }

        return EventEnvelope(
            identity: EventEnvelope.Identity(
                kind: "print.job",
                label: "PRINTJOBS"
            ),
            capture: EventEnvelope.Capture(
                source: .parser,
                eventTime: parseDate(item["completed_at"] ?? item["timestamp"] ?? item["created"])
                ?? Date(timeIntervalSince1970: 0),
                collectedAt: Date()
            ),
            payload: EventEnvelope.Payload(
                entityRefs: [EntityID(kind: .file, value: "print|\(details.document.isEmpty ? details.jobID : details.document)")],
                properties: printFields(item: item, details: details),
                provenance: ArtifactRoot.pathKey(sourceURL),
                confidence: 0.88
            )
        )
    }

    private func printFields(item: [String: Any], details: PrintJobDetails) -> [String: String] {
        let risk = printRiskTags(item: item, document: details.document, printer: details.printer)
        var fields: [String: String] = [
            "print.job_id": details.jobID,
            "print.document": details.document,
            "print.user": details.user,
            "print.printer": details.printer,
            "print.pages": details.pages,
            FieldTaxonomy.eventType: "print.job",
            FieldTaxonomy.userName: details.user,
        ]
        if let completed = stringish(item["completed_at"]) ?? stringish(item["timestamp"]) {
            fields["print.completed_at"] = completed
        }
        if let state = stringish(item["state"]) ?? stringish(item["job-state"]) {
            fields["print.state"] = state
        }
        if !risk.isEmpty {
            fields["print.risk_tags"] = risk.joined(separator: ",")
        }
        return fields
    }

    private func printRiskTags(item: [String: Any], document: String, printer: String) -> [String] {
        var risk = itemRiskTags(item)
        let lowerDocument = document.lowercased()
        if ["password", "secret", "credential", "ssn", "payroll", "w2", "bank", "id_rsa"]
            .contains(where: lowerDocument.contains) {
            appendRiskTag("sensitive_document", to: &risk)
        }
        if ["evil", "payload"].contains(where: lowerDocument.contains) {
            appendRiskTag("suspicious_document", to: &risk)
        }
        let lowerPrinter = printer.lowercased()
        if lowerPrinter.contains("remote") || lowerPrinter.contains("smb://") {
            appendRiskTag("remote_printer", to: &risk)
        }
        return risk
    }

    private func itemRiskTags(_ item: [String: Any]) -> [String] {
        guard let tags = stringish(item["risk_tags"]), !tags.isEmpty else { return [] }
        return tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    }

    private func appendRiskTag(_ tag: String, to risk: inout [String]) {
        guard !risk.contains(tag) else { return }
        risk.append(tag)
    }
}
