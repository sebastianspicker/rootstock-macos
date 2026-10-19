# Known issues in the 0.1.0 alpha

Thank you for testing Rootstock. This page lists what does not work yet, what
behaves differently than you might expect, and how to work around it. It
covers the collector, the offline investigation report, the optional Neo4j
graph, and the Red and Blue tools.

## Installing and running the collector

- **The downloaded collector is not signed or notarized.** macOS blocks it
  the first time with a message that Apple could not verify it. Check the
  published checksum, then remove the download quarantine from the
  `rootstock-collector` binary (`xattr -d com.apple.quarantine
  rootstock-collector`), or allow it once under System Settings > Privacy &
  Security > Open Anyway. The collector README shows the exact commands. If you
  would rather not run an unsigned binary, build it from source.
- **Some evidence needs Full Disk Access.** Without it, the scan finishes but
  lists the gaps in its `errors` array. Treat such a scan as partial.

## Gaps in what the collector records

These cause missed findings (false negatives), not false alarms:

- Agents in the macOS system launch-agent folder are not scanned.
- A sudoers rule written as `NOPASSWD:/bin/ls` (with no space after the colon)
  is not recognised as password-less.
- Cron files with Windows line endings, SSH server settings written as
  `Keyword=value`, extra `Port` lines, and unreadable SSH `Include` files are
  not fully handled.
- Some managed privacy (PPPC) entries and some file-permission rules (add file,
  add subfolder, delete child) are not reported.
- If the collector cannot read a group's members, the group appears with no
  members instead of an error.
- If code-signature checks fail for an XPC service or an authorization plug-in,
  it looks the same as an unsigned item.
- System extension types are guessed from their identifiers, so an
  endpoint-security extension can be listed as a driver.
- Entitlement lists for XPC services and sandbox exceptions can include
  entitlements whose value is `false`.

A change in this alpha: "notarized" is now reported as false for apps signed
with a Developer ID but never notarized, and as unknown when Gatekeeper
assessments are switched off. Earlier builds reported both as notarized.

## Offline investigation report

The offline report (`rootstock-graph-investigate`) needs no database and is the
recommended way to review a scan in this alpha. Known rough edges:

- Passing a folder as `--output` gives a raw "Is a directory" error. Pass a
  file name instead.

## Optional Neo4j graph and API

- **Use one database per Mac.** Some host settings and items are shared between
  Macs in one database, so a second Mac's import overwrites them and can link
  one Mac's accounts to another Mac's items.
- **Rescanning the same Mac can leave stale items.** Launch items, services and
  similar entries that were removed since the previous scan can still appear.
  For a clean picture, import the new scan into a fresh database.
- **An import that fails half-way leaves a partial graph.** The previous scan of
  that Mac is already removed. Run the import again.
- **The API needs a separate read account.** The graph README shows how to
  create it once before starting the API.
- `rootstock-graph-query --param` turns every value that looks like a number
  into a number, so a text value such as a numeric user name does not match.
- `rootstock-graph-diff-scans` matches applications by bundle identifier only,
  so two copies of one app, or a copy that moved, are not told apart.
- The executive summary adds up CVE matches per app, so a CVE shared by two apps
  is counted twice.
- If some NVD lookups fail, the cache is still marked fresh. Those lookups are
  retried only after the cache expires, or when you refresh with `--force`.
- Broad CPE-based CVE candidates raise risk tiers as much as precise matches.
- Reports and OpenGraph exports are written with your default file permissions,
  not owner-only like the viewer and the investigation report. Keep them in a
  private folder.

## Rootstock Blue

- **`ir posture` and `ir harden` need `--source` or `--live`.** They no longer
  read the Mac you run them on by default. Pass `--source <evidence folder>` for
  offline evidence, or `--live` to check this Mac on purpose.
- **`parse` now exits with an error when artifacts could not be read.** It still
  keeps the events from every readable artifact and lists the failed files.
  `ir triage` does not report such failures yet; run `parse` first if you need to
  know.
- **Unified log archives are not artifact folders.** For a `.logarchive`, use
  `rootstock-blue uls parse <logarchive> --out <events.jsonl>`.
- **Records without a timestamp appear at 1970-01-01** and carry
  `timestamp_missing=true`. Earlier builds showed them at the time of parsing.
- **An interrupted write locks the case.** If `case verify` or the next import
  reports an "unfinished case write journal", and no other `rootstock-blue`
  process is using the case, create a new case and repeat the imports from your
  original evidence. Blue never changes the evidence you import from.
- Detection rules with misspelled match keys are accepted, and the misspelled
  condition is ignored, which makes the rule broader. An empty rules folder gives
  zero findings without a warning.

## Rootstock Red

- The shell-profile lab action only changes files it created or already marked:
  the target must be missing, empty, or already contain the lab marker line.
  Use a dedicated lab file rather than your real shell profile.

## Reporting a bug

Open an issue with the bug report template on GitHub. Report security problems
privately as described in the security policy, never in a public issue.

Please include:

- the component and version (`rootstock-collector --version`,
  `rootstock-blue version`, or the commit you built from);
- your macOS version and Mac model (Apple silicon or Intel);
- the exact command you ran and its full terminal output;
- for collector problems, the `errors` array from the scan;
- for graph problems, the pipeline output and the Neo4j version.

Scans, reports and Blue cases describe your Mac in detail: apps, accounts,
permissions and settings. Do not attach them to a public issue. If the problem
needs evidence to reproduce, describe it, or share a small synthetic example
built from the files in the repository's `examples` folder.
