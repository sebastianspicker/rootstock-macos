import Foundation
import Testing
@testable import RootstockCore

@Suite struct FindingTests {
    @Test func findingCodableRoundTrip() throws {
        let finding = Finding(id: "rootstock.check.host.identity", title: "Host identity", severity: .info, category: .host, resolution: .init(evidence: [Evidence(type: "host", detail: "ok")], attackTechniques: ["T1082"], remediation: ["n/a"]), runtime: .init(confidence: .high, dryRunSafe: true, opsecScore: 5))
        let data = try JSONEncoder().encode(finding)
        let decoded = try JSONDecoder().decode(Finding.self, from: data)
        #expect(decoded == finding)
    }

    @Test func consentPolicy() {
        let policy = ConsentPolicy.labDefault
        let bad = ConsentTokens()
        #expect(!(bad.satisfies(policy)))
        let good = ConsentTokens(iAmAuthorized: true, scope: "ENG-1", operatorName: "alice")
        #expect(good.satisfies(policy))
    }

    @Test func labConsentFailsClosedForKillSwitchAndIncompleteModeConsentMatrix() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-consent-\(UUID().uuidString)", isDirectory: true)
        let killSwitch = directory.appendingPathComponent("DISABLE")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let authorized = ConsentTokens(iAmAuthorized: true, scope: "ENG-TEST", operatorName: "alice")
        for mode in RunMode.allCases {
            let context = EvaluationContext(mode: mode, consent: authorized)
            if mode == .lab || mode == .purple {
                #expect(throws: Never.self) { try SafetyRails.ensureLabConsent(context: context, killSwitchURL: killSwitch) }
            } else {
                #expect(throws: (any Error).self) { try SafetyRails.ensureLabConsent(context: context, killSwitchURL: killSwitch) }
            }
        }
        #expect(throws: (any Error).self) { try SafetyRails.ensureLabConsent(
                context: EvaluationContext(mode: .lab),
                killSwitchURL: killSwitch
            ) }

        try Data().write(to: killSwitch)
        do {
            _ = try SafetyRails.ensureLabConsent(
                context: EvaluationContext(mode: .purple, consent: authorized),
                killSwitchURL: killSwitch
            )
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(error as? RootstockError == .killSwitchActive(path: killSwitch.path))
        }
    }

    @Test func rootstockDescribeTriState() {
        #expect(Optional(true).rootstockDescribe == "true")
        #expect(Optional(false).rootstockDescribe == "false")
        let unknown: Bool? = nil
        #expect(unknown.rootstockDescribe == "unknown")
    }

    @Test func processRunnerBlockedInAssess() {
        let runner = ProcessRunner.forContext(.assess())
        do {
            _ = try runner.run(executable: "/bin/echo")
            Issue.record("Expected error to be thrown")
        } catch {
            #expect(error as? RootstockError == .processNotAllowedInAssess)
        }
    }

    @Test func schemaVersion() {
        #expect(RootstockCore.schemaVersion == "1.0.0")
    }

    @Test func auditLogAppendWritesJSONL() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-audit-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let auditURL = try AuditLog.defaultURL(projectDirectory: dir)
        #expect(auditURL.lastPathComponent == "audit.jsonl")

        let audit = AuditLog(fileURL: auditURL)
        let record = AuditRecord(
            run: .init(mode: .assess, profile: .standard, allowNetwork: false),
            subject: .init(
                operatorName: "test-operator",
                scope: "ENG-TEST",
                hostUUID: "host-uuid-1",
                argvSummary: "rootstock-red audit --profile standard"
            ),
            outcome: .init(
                findingCount: 3,
                collectorIds: ["collect.host"],
                checkIds: ["rootstock.check.host.identity"]
            )
        )
        try await audit.append(record)
        try await audit.append(record)

        let text = try String(contentsOf: auditURL, encoding: .utf8)
        let lines = text.split(whereSeparator: \.isNewline).map(String.init)
        #expect(lines.count == 2)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        for line in lines {
            let decoded = try decoder.decode(AuditRecord.self, from: Data(line.utf8))
            #expect(decoded.mode == .assess)
            #expect(decoded.profile == .standard)
            #expect(decoded.operatorName == "test-operator")
            #expect(decoded.scope == "ENG-TEST")
            #expect(decoded.hostUUID == "host-uuid-1")
            #expect(decoded.findingCount == 3)
            #expect(decoded.collectorIds == ["collect.host"])
            #expect(decoded.checkIds == ["rootstock.check.host.identity"])
            #expect(!decoded.allowNetwork)
            #expect(decoded.schemaVersion == RootstockCore.schemaVersion)
        }
        #expect(audit.fileURL == auditURL)
    }
}
