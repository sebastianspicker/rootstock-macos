/// CLI entry surface for main.
import Foundation
import RootstockBlueCore
import RootstockBlueCase
import RootstockBlueESKit
import RootstockBlueFX
import RootstockBlueDetect
import RootstockBlueCollect
import RootstockBlueExport
import RootstockBlueAcquire
import RootstockBlueIntegrations

RootstockBlueCLI.main()

struct RootstockBlueCLI {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard let command = args.first else {
            printUsage()
            exit(1)
        }
        guard let handler = commandHandler(for: command) else {
            fputs("Unknown command: \(command)\n", stderr)
            printUsage()
            exit(1)
        }

        do {
            try handler(Array(args.dropFirst()))
        } catch {
            fputs("error: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }

    private static func commandHandler(for command: String) -> (([String]) throws -> Void)? {
        let handlers: [String: ([String]) throws -> Void] = [
            "version": showVersion, "--version": showVersion, "-v": showVersion,
            "help": showUsage, "--help": showUsage, "-h": showUsage,
            "case": handleCase, "record": handleRecord, "query": handleQuery,
            "detect": handleDetect, "collect": handleCollect, "parse": handleParse,
            "export": handleExport, "report": handleReport, "ir": handleIR,
            "timeline": handleTimeline, "preflight": handlePreflight,
            "import": handleImport, "uls": handleULS, "santa": handleSanta,
        ]
        return handlers[command]
    }

    private static func showVersion(_ args: [String]) {
        _ = args
        print("rootstock-blue \(RootstockBlueVersion.string)")
    }

    private static func showUsage(_ args: [String]) {
        _ = args
        printUsage()
    }

    static func repoContentRoot() -> URL {
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let candidate = cwd.appendingPathComponent("Content")
        if FileManager.default.fileExists(atPath: candidate.path) {
            return candidate
        }
        return candidate
    }

    static func handleCase(_ args: [String]) throws {
        guard let sub = args.first else {
            throw RootstockBlueError.io("case requires create|open|verify")
        }
        switch sub {
        case "create": try createCase(args)
        case "open": try openCase(args)
        case "verify": try verifyCase(args)
        default:
            throw RootstockBlueError.io("unknown case subcommand \(sub)")
        }
    }

    private static func createCase(_ args: [String]) throws {
        guard args.count >= 2 else { throw RootstockBlueError.io("usage: case create <path>") }
        let name = optionValue("--name", in: args)
        let package = try CasePackage.create(at: URL(fileURLWithPath: args[1]), name: name)
        print("created \(package.rootURL.path)")
        print("case_id \(package.manifest.caseID.uuidString)")
    }

    private static func openCase(_ args: [String]) throws {
        guard args.count >= 2 else { throw RootstockBlueError.io("usage: case open <path>") }
        let package = try CasePackage.open(at: URL(fileURLWithPath: args[1]))
        print("opened \(package.manifest.name) (\(package.manifest.caseID.uuidString))")
    }

    private static func verifyCase(_ args: [String]) throws {
        guard args.count >= 2 else { throw RootstockBlueError.io("usage: case verify <path>") }
        let package = try CasePackage.open(at: URL(fileURLWithPath: args[1]))
        try package.verifyLayout()
        let events = try package.loadAllEvents()
        print("ok \(package.rootURL.path) events=\(events.count) jsonl_files=\(package.eventJSONLFileCount())")
    }

    private static func optionValue(_ option: String, in args: [String]) -> String? {
        guard let index = args.firstIndex(of: option), args.count > index + 1 else { return nil }
        return args[index + 1]
    }

    static func handleRecord(_ args: [String]) throws {
        guard let sub = args.first else {
            throw RootstockBlueError.io("record requires inject|status")
        }
        switch sub {
        case "inject":
            guard let caseIdx = args.firstIndex(of: "--case"), args.count > caseIdx + 1 else {
                throw RootstockBlueError.io("usage: record inject --case <path.rsbcase> --jsonl <file>")
            }
            guard let jsonlIdx = args.firstIndex(of: "--jsonl"), args.count > jsonlIdx + 1 else {
                throw RootstockBlueError.io("usage: record inject --case <path.rsbcase> --jsonl <file>")
            }
            var profileName = ESProfileName.ir
            if let idx = args.firstIndex(of: "--profile"), args.count > idx + 1 {
                profileName = ESProfileName(rawValue: args[idx + 1]) ?? .ir
            }
            let profile = ESSubscriptionProfile.builtin(profileName)
            precondition(!profile.authMode)
            let pkg = try CasePackage.open(at: URL(fileURLWithPath: args[caseIdx + 1]))
            let jsonl = URL(fileURLWithPath: args[jsonlIdx + 1])
            let envelopes = try SessionRecorder.loadEnvelopes(fromJSONL: jsonl)
            let client = MockESClient()
            let recorder = SessionRecorder(profile: profile)
            let sink = CaseEventSink(package: pkg)
            let result = try recorder.recordEnvelopes(envelopes, client: client, into: sink)
            print("record_inject written=\(result.written) profile=\(profileName.rawValue) authMode=\(profile.authMode)")
            print("counters received=\(result.counters.received) mapped=\(result.counters.mapped) dropped=\(result.counters.totalDropped)")
        case "status":
            print("record status: use inject for CI/alpha; live ES requires entitlement+FDA (mock factory default)")
            print("auth_block_default=\(NonGoals.authBlockDefaultOn)")
        case "start", "stop":
            print("deprecated in alpha: use `record inject --case ... --jsonl ...` for durable session→case path")
        default:
            throw RootstockBlueError.io("unknown record subcommand")
        }
    }

    static func handleQuery(_ args: [String]) throws {
        guard args.count >= 2 else {
            throw RootstockBlueError.io("usage: query <path.rsbcase> <SQL>")
        }
        let pkg = try CasePackage.open(at: URL(fileURLWithPath: args[0]))
        let sql = args.dropFirst().joined(separator: " ")
        let db = try pkg.openDatabase()
        if sql.trimmingCharacters(in: .whitespacesAndNewlines).uppercased().hasPrefix("SELECT") {
            let rows = try db.queryRows(sql)
            print("rows=\(rows.count)")
            for row in rows.prefix(50) {
                let line = row.keys.sorted().map { "\($0)=\(row[$0] ?? "")" }.joined(separator: " ")
                print(line)
            }
        } else if let value = try db.queryScalar(sql) {
            print(value)
        } else {
            try db.exec(sql)
            print("ok")
        }
    }

    static func handleDetect(_ args: [String]) throws {
        guard args.first == "run" else {
            throw RootstockBlueError.io("usage: detect run --ruleset samples [--case <path.rsbcase>]")
        }
        var contentRoot = repoContentRoot()
        if let idx = args.firstIndex(of: "--content-root"), args.count > idx + 1 {
            contentRoot = URL(fileURLWithPath: args[idx + 1])
        }
        var ruleset = "samples"
        if let idx = args.firstIndex(of: "--ruleset"), args.count > idx + 1 {
            ruleset = args[idx + 1]
        }
        let rulesDir = contentRoot.appendingPathComponent("detections/\(ruleset)")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        let engine = DetectionEngine()

        let findings: [Finding]
        if let caseIdx = args.firstIndex(of: "--case"), args.count > caseIdx + 1 {
            // Case-timeline evaluation path (not only standalone JSONL fixtures)
            let pkg = try CasePackage.open(at: URL(fileURLWithPath: args[caseIdx + 1]))
            let events = try CaseTimeline.merged(from: pkg)
            findings = try engine.evaluate(rulesDirectory: rulesDir, events: events)
            print("mode=case events=\(events.count)")
        } else {
            findings = try engine.run(rulesDirectory: rulesDir, fixturesDirectory: fixturesDir)
            print("mode=fixtures")
        }
        print("findings=\(findings.count)")
        for f in findings {
            print("- [\(f.severity)] \(f.ruleID): \(f.title)")
        }
        if findings.isEmpty {
            print("note: zero findings (check fixtures or case events)")
        }
    }

    static func handleReport(_ args: [String]) throws {
        guard args.count >= 3, args[0] == "markdown" else {
            throw RootstockBlueError.io("usage: report markdown <path.rsbcase> <out.md>")
        }
        let pkg = try CasePackage.open(at: URL(fileURLWithPath: args[1]))
        let out = URL(fileURLWithPath: args[2])
        // Optionally attach detections from samples against case timeline
        var findings: [Finding] = []
        let rulesDir = repoContentRoot().appendingPathComponent("detections/samples")
        if FileManager.default.fileExists(atPath: rulesDir.path) {
            let events = try CaseTimeline.merged(from: pkg)
            findings = try DetectionEngine().evaluate(rulesDirectory: rulesDir, events: events)
        }
        let stats = try CaseReport.exportMarkdown(package: pkg, to: out, findings: findings)
        print("report \(out.path) events=\(stats.eventCount) findings=\(stats.findings.count) custody=\(stats.custodyLines)")
    }

    static func handleCollect(_ args: [String]) throws {
        guard let packName = args.first else {
            throw RootstockBlueError.io("usage: collect <pack> --case <path> --source <tree> [--offline]")
        }
        var contentRoot = repoContentRoot()
        if let idx = args.firstIndex(of: "--content-root"), args.count > idx + 1 {
            contentRoot = URL(fileURLWithPath: args[idx + 1])
        }
        guard let caseIdx = args.firstIndex(of: "--case"), args.count > caseIdx + 1 else {
            throw RootstockBlueError.io("collect requires --case <path.rsbcase>")
        }
        guard let srcIdx = args.firstIndex(of: "--source"), args.count > srcIdx + 1 else {
            throw RootstockBlueError.io("collect requires --source <artifact-tree>")
        }
        let offline = args.contains("--offline")
        let packURL = contentRoot.appendingPathComponent("collections/\(packName).yaml")
        let pack = try CollectionPackLoader.load(from: packURL)
        let pkg = try CasePackage.open(at: URL(fileURLWithPath: args[caseIdx + 1]))
        let source = URL(fileURLWithPath: args[srcIdx + 1])
        let runner = CollectRunner(skipStrictPreflight: offline)
        let result = try runner.run(pack: pack, sourceRoot: source, into: pkg)
        print("pack=\(result.packName) files_copied=\(result.filesCopied) events_written=\(result.eventsWritten)")
        for item in result.preflight.items {
            let mark = item.ok ? "ok" : "need"
            print("  [\(mark)] \(item.name): \(item.detail)")
        }
    }

    static func handleParse(_ args: [String]) throws {
        guard let path = args.first else {
            throw RootstockBlueError.io("usage: parse <path> --case <path.rsbcase>")
        }
        let source = ImageSource.infer(from: URL(fileURLWithPath: path))
        let engine = ForensicsEngine()
        guard let idx = args.firstIndex(of: "--case"), args.count > idx + 1 else {
            let events = try engine.parse(source: source)
            print("parsed_events=\(events.count) plugins=\(engine.runtime.parserIDs().joined(separator: ","))")
            for e in events.prefix(10) {
                print("  \(e.sourcePlugin) \(e.eventType) entities=\(e.entityRefs.count)")
            }
            return
        }
        let pkg = try CasePackage.open(at: URL(fileURLWithPath: args[idx + 1]))
        let n = try engine.parse(source: source, into: pkg)
        print("parsed_events=\(n) plugins=\(engine.runtime.parserIDs().joined(separator: ","))")
        print("wrote \(n) events into case \(pkg.rootURL.path)")
    }

    static func handleTimeline(_ args: [String]) throws {
        guard let path = args.first else {
            throw RootstockBlueError.io("usage: timeline <path.rsbcase> [--limit N]")
        }
        var limit = 100
        if let idx = args.firstIndex(of: "--limit"), args.count > idx + 1 {
            limit = Int(args[idx + 1]) ?? 100
        }
        let pkg = try CasePackage.open(at: URL(fileURLWithPath: path))
        let merged = try CaseTimeline.merged(from: pkg)
        print("timeline_events=\(merged.count)")
        for e in merged.prefix(limit) {
            let refs = e.entityRefs.map(\.description).joined(separator: ",")
            print("\(ISO8601DateFormatter().string(from: e.eventTime)) [\(e.source.rawValue)/\(e.sourcePlugin)] \(e.eventType) refs=\(refs)")
        }
    }

    static func handleExport(_ args: [String]) throws {
        guard let kind = args.first else {
            throw RootstockBlueError.io(
                "usage: export jsonl <path.rsbcase> <out.jsonl>\n"
                    + "       export family <path.rsbcase> <out.json>"
            )
        }
        switch kind {
        case "jsonl":
            guard args.count >= 3 else {
                throw RootstockBlueError.io("usage: export jsonl <path.rsbcase> <out.jsonl>")
            }
            let pkg = try CasePackage.open(at: URL(fileURLWithPath: args[1]))
            let out = URL(fileURLWithPath: args[2])
            let events = try CaseTimeline.merged(from: pkg)
            try JSONLExporter.exportEvents(events, to: out)
            print("exported \(out.path) events=\(events.count)")
        case "family":
            guard args.count >= 3 else {
                throw RootstockBlueError.io("usage: export family <path.rsbcase> <out.json>")
            }
            let pkg = try CasePackage.open(at: URL(fileURLWithPath: args[1]))
            let out = URL(fileURLWithPath: args[2])
            let events = try CaseTimeline.merged(from: pkg)
            try FamilyOpenExporter.writeJSON(
                events: events,
                to: out,
                caseName: pkg.manifest.name
            )
            print("exported_family \(out.path) events_in=\(events.count)")
        default:
            throw RootstockBlueError.io("unknown export kind: \(kind)")
        }
    }

    static func handlePreflight(_ args: [String]) throws {
        guard let packName = args.first else {
            throw RootstockBlueError.io("usage: preflight <pack> [--offline]")
        }
        var contentRoot = repoContentRoot()
        if let idx = args.firstIndex(of: "--content-root"), args.count > idx + 1 {
            contentRoot = URL(fileURLWithPath: args[idx + 1])
        }
        let offline = args.contains("--offline")
        let pack = try CollectionPackLoader.load(
            from: contentRoot.appendingPathComponent("collections/\(packName).yaml")
        )
        let report = Preflight.check(for: pack, offlineFixtureMode: offline)
        print(report.passed ? "preflight_passed=true" : "preflight_incomplete")
        for item in report.items {
            print("- \(item.name): \(item.ok ? "ok" : "pending") - \(item.detail)")
        }
        print(UnifiedLogsSidecar.statusMessage())
        _ = SantaBridge.status
        _ = AcquisitionWizard()
    }

    static func handleImport(_ args: [String]) throws {
        guard let kind = args.first else {
            throw RootstockBlueError.io(
                "usage: import scan-json <scan.json> --case <path.rsbcase>\n"
                    + "       import findings-jsonl <findings.jsonl> --case <path.rsbcase>"
            )
        }
        if kind == "zip" {
            throw RootstockBlueError.notImplemented(
                "ZIP archive import is disabled in this alpha. Parse an already-extracted artifact tree with parse."
            )
        }
        guard let caseIdx = args.firstIndex(of: "--case"), args.count > caseIdx + 1 else {
            throw RootstockBlueError.io("import requires --case <path.rsbcase>")
        }
        let pkg = try CasePackage.open(at: URL(fileURLWithPath: args[caseIdx + 1]))
        switch kind {
        case "scan-json":
            guard args.count >= 2 else {
                throw RootstockBlueError.io("usage: import scan-json <scan.json> --case <path.rsbcase>")
            }
            let scan = URL(fileURLWithPath: args[1])
            let summary = try ScanJSONImporter.importIntoCase(scanURL: scan, casePackage: pkg)
            print(
                "import_scan_json events=\(summary.totalEvents) tcc=\(summary.tccEvents) "
                    + "launch_items=\(summary.launchItemEvents)"
            )
        case "findings-jsonl":
            guard args.count >= 2 else {
                throw RootstockBlueError.io(
                    "usage: import findings-jsonl <findings.jsonl> --case <path.rsbcase>"
                )
            }
            let findings = URL(fileURLWithPath: args[1])
            let count = try FindingsJSONLImporter.importIntoCase(
                findingsURL: findings,
                casePackage: pkg
            )
            print("import_findings_jsonl events=\(count)")
        default:
            throw RootstockBlueError.io("unknown import kind: \(kind)")
        }
    }

    static func handleULS(_ args: [String]) throws {
        guard let sub = args.first else {
            throw RootstockBlueError.io("usage: uls status|parse")
        }
        switch sub {
        case "status":
            print(UnifiedLogsSidecar.statusMessage())
        case "parse":
            guard args.count >= 2 else {
                throw RootstockBlueError.io("usage: uls parse <logarchive> --out <jsonl>")
            }
            guard let outIdx = args.firstIndex(of: "--out"), args.count > outIdx + 1 else {
                throw RootstockBlueError.io("uls parse requires --out <jsonl>")
            }
            try UnifiedLogsSidecar.parse(
                logarchive: URL(fileURLWithPath: args[1]),
                outputJSONL: URL(fileURLWithPath: args[outIdx + 1])
            )
            print("uls_ok \(args[outIdx + 1])")
        default:
            throw RootstockBlueError.io("unknown uls subcommand")
        }
    }

    /// `santa ingest <log> --case <path>` - pure EventEnvelope production via SantaBridge, write to case.
    static func handleSanta(_ args: [String]) throws {
        guard args.first == "ingest" else {
            throw RootstockBlueError.io("usage: santa ingest <log.jsonl> --case <path.rsbcase>")
        }
        guard args.count >= 2 else {
            throw RootstockBlueError.io("usage: santa ingest <log.jsonl> --case <path.rsbcase>")
        }
        guard let caseIdx = args.firstIndex(of: "--case"), args.count > caseIdx + 1 else {
            throw RootstockBlueError.io("santa ingest requires --case <path.rsbcase>")
        }
        let logURL = URL(fileURLWithPath: args[1])
        let pkg = try CasePackage.open(at: URL(fileURLWithPath: args[caseIdx + 1]))
        let events = try SantaBridge.eventsFromSantaLog(at: logURL)
        let sink = CaseEventSink(package: pkg, actor: NSUserName())
        for event in events {
            try sink.append(event)
        }
        try sink.noteCustody(
            action: "santa_ingest",
            detail: "Santa decision log \(logURL.lastPathComponent) → \(events.count) events"
        )
        try pkg.updateHashes()
        print("santa_ingest events_written=\(events.count) log=\(logURL.path)")
        for e in events.prefix(20) {
            let decision = e.fields["santa.decision"] ?? "?"
            let path = e.fields[FieldTaxonomy.processPath] ?? e.fields[FieldTaxonomy.filePath] ?? ""
            print("  \(e.eventType) \(decision) \(path)")
        }
    }
}
