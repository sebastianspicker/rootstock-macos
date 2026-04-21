# Phase 1: Collector MVP — TCC + Entitlements + Code Signing

## Objective

A working Swift CLI binary (`rootstock-collector`) that scans a macOS endpoint and produces
a JSON file containing TCC grants, app entitlements, and code signing metadata for all
installed applications.

## Context

This is the foundation of the entire project. Without accurate data collection, the graph
is meaningless. Phase 1 focuses on the three highest-value data sources (P0 in ARCHITECTURE.md):

1. **TCC databases** — who has access to what
2. **Entitlements** — what security-relevant capabilities each app declares
3. **Code signing** — which apps are injectable (missing hardened runtime / library validation)

## Steps

### Step 1: Swift Package scaffolding
- Create `collector/Package.swift` with targets for CLI, TCC, Entitlements, CodeSigning, Models, Export
- Define the `DataSource` protocol in `Models/`
- Define the `ScanResult` Codable struct matching the JSON schema in ARCHITECTURE.md
- Create a minimal CLI entry point that accepts `--output <path>` argument

### Step 2: TCC database parser
- Implement SQLite reader for `~/Library/Application Support/com.apple.TCC/TCC.db`
- Parse the `access` table: `service`, `client`, `client_type`, `auth_value`, `auth_reason`
- Map `auth_value` to human-readable status (0=denied, 2=allowed, 3=limited)
- Attempt system TCC.db if running with FDA; log graceful skip if not
- Reference: `docs/research/tcc-internals.md`

### Step 3: App entitlement scanner
- Enumerate all `.app` bundles in `/Applications`, `~/Applications`, `/System/Applications`
- For each app, run equivalent of `codesign -d --entitlements :- <path>`
- Use Security.framework APIs where possible, fall back to CLI parsing
- Extract and categorize entitlements (TCC-related, security, sandbox, other)
- Flag security-critical entitlements (see `docs/research/entitlements-reference.md`)

### Step 4: Code signing metadata
- For each discovered app, extract: team ID, hardened runtime flag, library validation flag
- Use `SecStaticCodeCreateWithPath` + `SecCodeCopySigningInformation`
- Determine `is_electron` heuristic (check for Electron framework in Frameworks/)
- Determine `signed` status

### Step 5: JSON export
- Assemble all collected data into the `ScanResult` struct
- Serialize to JSON with `JSONEncoder` (pretty-printed, sorted keys)
- Write to output path
- Include `errors` array with per-module failure reports

### Step 6: Integration test
- Run collector on the development Mac
- Validate JSON output against expected schema
- Manually verify a few known apps (e.g., Terminal has FDA, check it appears in TCC grants)

## Acceptance Criteria

- [ ] `rootstock-collector --output scan.json` produces valid JSON
- [ ] JSON contains TCC grants from user-level TCC.db
- [ ] JSON contains entitlements for all apps in /Applications
- [ ] JSON contains code signing metadata (hardened_runtime, library_validation, team_id)
- [ ] Collector completes in < 30 seconds on a typical Mac
- [ ] Collector runs without crash when FDA is not available (graceful degradation)
- [ ] Each module reports its success/failure in the `errors` array
- [ ] No secrets or sensitive data appear in the output

## Dependencies

- macOS 14+ development machine with Xcode installed
- At least a few apps with TCC grants for testing (Terminal, iTerm, etc.)

## Resolved Questions

- **SQLite access (DD-005):** Use raw C interop via system-provided `libsqlite3`
  (`import SQLite3` on Darwin). No third-party wrapper needed — this satisfies the
  zero-dependency constraint while providing full SQLite read access for TCC databases.

## Open Questions

- **SSV handling:** How to handle apps in `/System/Applications` that may have restricted
  code signing info due to SSV (Signed System Volume)? Needs testing during Step 3/4.

## Deferred Decisions

- **Security.framework vs. CLI parsing (DD-006):** Current plan is Security.framework as
  primary API with `codesign` CLI as fallback. Full evaluation deferred to after M1 —
  real-world reliability data needed before committing to one approach.
