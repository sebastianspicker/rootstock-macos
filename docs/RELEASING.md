# Releasing Rootstock

This is the maintained approval-only procedure for the Core alpha candidate.
It does not authorize a commit, tag, upload, GitHub release, or other remote
change.

## Version scope

The proposed Core version is `v0.1.0-alpha.1`. `VERSION` is the human-readable
source of truth. Python package metadata uses `0.1.0a1`.

The root version covers the Core collector, graph, viewer, cve-scan bridge, demo
artifact, changelog, and core citation metadata. Rootstock Red and Rootstock
Blue retain their own runtime versions and are distributed as source in this
repository. They are tested as part of the repository candidate but are not
included in the Core collector archive.

Until publication, the changelog entry remains `Unreleased` and
`CITATION.cff` has no release date.

## Candidate structure

Run the structural check after changing metadata, public documentation, locks,
viewer assets, or component markers:

```bash
python3 scripts/check-release.py
```

This check requires public files and the four curated viewer images to be
Git-tracked. It also rejects tracked or local release packets such as plans,
audits, ledgers, and report output. On a working tree containing an
untracked candidate, it is expected to report that publication delta rather
than treat filesystem presence as sufficient.

Immediately before an approved tag, run:

```bash
python3 scripts/check-release.py --require-clean
```

## Candidate gates

Use the toolchains pinned in the repository:

- Xcode 26.6 with Apple Swift 6.3 for the Core collector
- Node.js from `.node-version`, npm 11.17.0, and `package-lock.json`
- Python 3.11 with the checked-in `uv.lock` files
- Neo4j 5.26 Community for required graph integration

Run every command in [QUALITY.md](QUALITY.md), including the shared, Red, and
Blue Swift packages. Record exact failures and environment blocks. Do not treat
fast tests or mocked browser tests as evidence for the live Neo4j lane.

## Screenshots and privacy

The public set contains only these Playwright captures of the maintained viewer
using the synthetic static release fixture:

- `viewer-overview.png`
- `viewer-node-inspector.png`
- `viewer-attack-path.png`
- `viewer-risk-filter.png`

Regenerate them with:

```bash
npm run screenshots:release
```

Review each image before publication. It must contain no real hostname,
username, local path, token, scan identifier, package inventory, finding, or
case data. These captures verify the production template, styles, bundle, and
recorded interactions in static mode. They do not verify a live Neo4j instance
or API session.

## Collector archive

On a supported macOS builder, create the universal Core collector archive and
checksum:

```bash
bash scripts/build-release.sh
```

The script verifies the requested version, binary version output, arm64 and
x86_64 slices, archive contents, and SHA-256 checksum. It writes ignored local
files under `release/`:

```text
release/rootstock-collector-v0.1.0-alpha.1-macos-universal.tar.gz
release/rootstock-collector-v0.1.0-alpha.1-macos-universal.tar.gz.sha256
```

The archive contains the renamed collector executable, GPL-3.0 license text,
the self-contained `collector/README.md`, and the repository changelog. It does
not contain the graph, viewer, cve-scan, Red, Blue, shared package, or their
documentation.

The candidate procedure does not include signing or notarization. Any uploaded
alpha binary must state that limitation.

## Release notes

Use the matching [changelog](../CHANGELOG.md) section as the factual base.
Include:

- source and binary scope
- minimum toolchain and platform requirements
- artifact, privacy, network, and mutation boundaries
- exact checks that passed
- skipped or environment-blocked checks
- known compatibility and schema risks
- a SHA-256 checksum for each uploaded archive

## Publication sequence

Perform these steps only after explicit maintainer approval:

1. Review the intended diff and create the release commit.
2. Add the actual UTC date to `CHANGELOG.md` and `CITATION.cff`.
3. Update the supported-version table in `SECURITY.md` if needed.
4. Run all gates and `scripts/check-release.py --require-clean`.
5. Build and inspect the Core collector archive and checksum.
6. Create annotated tag `v0.1.0-alpha.1`.
7. Create a GitHub prerelease from that tag.
8. Upload the verified archive and checksum.
9. Verify the rendered documentation, images, links, tag, and assets on GitHub.

No step in this file substitutes for explicit approval.
