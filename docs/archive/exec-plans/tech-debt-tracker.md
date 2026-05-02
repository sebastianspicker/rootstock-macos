# Tech Debt Tracker

> Track known shortcuts, deferred decisions, and areas that need revisiting.
> Review this list at the start of each new phase.

## Active Debt

| ID | Component | Description | Incurred | Priority |
|---|---|---|---|---|
| TD-004 | collector/TCC | macOS 26.3 (and macOS 15+) blocks TCC.db reads via `SQLITE_OPEN_READONLY` at kernel level even for user-owned files — returns `SQLITE_AUTH`. Process requires FDA (Full Disk Access) entitlement or must be signed with `com.apple.private.tcc.allow` to read TCC.db. Currently, the collector degrades gracefully: TCC module reports a recoverable error and returns zero grants. Resolution: (a) Ship the binary with FDA entitlement for opt-in use, or (b) use macOS Security framework proxy APIs if available. Until resolved, all correctness testing uses synthetic fixture databases. | Phase 1.2 | High |
| TD-002 | collector | App discovery only scans three directories — should also check Homebrew Cask, user-specific installs | Phase 1 | Medium |
| TD-003 | graph | No schema migration strategy for Neo4j — model changes require manual DB wipe | Phase 2 | Medium |

| TD-005 | collector/CodeSigning | Platform binaries (Apple system apps with no developer team) have `team_id` omitted from JSON entirely rather than serialized as `null`. Swift's `JSONEncoder` omits nil optionals by default. Consumers must use `app.get("team_id")` not `app["team_id"]`. Fix: use a custom encoder or encode as explicit null. | Phase 1.4 | Low |
| TD-007 | collector/CodeSigning | sudo/root run could not be tested via CI pipeline (requires interactive terminal for sudo). Root run expected to show `has_fda: true` and parse system TCC.db. Verify manually. | Phase 1.6 | Low |
| TD-008 | collector/XPC | XPC scanning is the dominant performance bottleneck (~4.8s of 5.3s total on a 184-app Mac). XPC plist reading is sequential; parallelizing with TaskGroup (same pattern as EntitlementDataSource) should yield 2–3x speedup. Deferred because total scan time is already well within the 30s target. | Phase 5.3 | Low |
| TD-009 | collector | App bundles without CFBundleIdentifier now get a path-based pseudo-ID (`path.<AppName>`). These pseudo-IDs are stable within a machine but not portable across machines or installs. Neo4j import will MERGE on this ID — acceptable for MVP but may cause duplicate nodes if the app is reinstalled at a different path. | Phase 5.3 | Low |

## Resolved Debt

| ID | Component | Description | Incurred | Resolved | Resolution |
|---|---|---|---|---|---|
| TD-001 | collector | CLI argument parsing was minimal | Phase 1 | Phase 1.1 | Added `--verbose`, `--modules`, `--output` flags with swift-argument-parser |
| TD-006 | collector/CodeSigning | SIP-protected apps (Terminal.app, Safari.app) reported as injectable false positives | Phase 1.6 | Gap Features | Added `is_sip_protected` path-based check in CodeSigningAnalyzer; InjectionAssessment returns empty methods for SIP apps; infer_injection.py excludes SIP-protected targets from CAN_INJECT_INTO edges |
