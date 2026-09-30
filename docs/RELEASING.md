# Releasing Rootstock

This guide is for maintainers preparing the Core alpha release. Build and
verify the candidate locally before approving a tag or upload.

## Versions and contents

`VERSION` contains the Core release version, currently `0.1.0-alpha.1`. Python
package metadata uses `0.1.0a1`; the corresponding Git tag is
`v0.1.0-alpha.1`.

The Core version covers the collector, graph, viewer, cve-scan bridge, demo,
changelog, and citation metadata. Red and Blue have independent runtime
versions. They are tested with the repository but distributed as source,
outside the collector archive.

Keep unreleased changes under `Unreleased` in the changelog. Add the release
date to the versioned entry and `CITATION.cff` when preparing publication.

## Check the candidate

Use the repository toolchains: Swift 6.3 (Xcode 26.6) for the collector,
Python 3.11 with the checked-in `uv.lock` files, and the Node version in
`graph/viewer/.node-version` with npm 11.17.0 and the `package-lock.json` files
in `graph/viewer/` and the repository root.

From the repository root, run:

```sh
sh scripts/verify release
sh scripts/verify full
```

The release lane checks public files, version agreement, source size, and the
static demo. It requires the public inputs to be Git-tracked and rejects
private working material. Files that exist locally but have not been added to
Git will fail this check.

The full lane includes all [verification checks](QUALITY.md), including Swift
packages and live Neo4j integration. Configure the database and both writer
and reader credentials as described in [Configuration](CONFIGURATION.md).
Record failed or unrun checks and their causes. A passing web build says
nothing about the live database connection.

Before tagging, require a clean checkout:

```sh
ROOTSTOCK_VERIFY_REQUIRE_CLEAN=1 sh scripts/verify release
```

For an uncommitted candidate, the temporary-index option documented in
[Quality gates](QUALITY.md#release-checks) can check the complete snapshot
without changing the normal staging area. That result is preparation evidence,
not a release commit.

## Inspect the demo

Build the Pages artifact and verify its synthetic data and screenshot files:

```sh
cd graph/viewer
npm ci --ignore-scripts
npm run demo:build
npm run demo:verify
```

Preview the viewer and tour using the [screenshot guide](screenshots.md).
Check that the images match the viewer and contain only fictional data. Real
hostnames, usernames, paths, tokens, inventories, findings, and case data do
not belong in public assets. The static demo does not test the live API.

## Build the collector archive

On a supported macOS builder, run:

```sh
bash collector/scripts/build-release.sh
```

The script checks the requested version, the binary's version output, arm64
and x86_64 slices, archive contents, and SHA-256 checksum. It writes:

```text
release/rootstock-collector-v0.1.0-alpha.1-macos-universal.tar.gz
release/rootstock-collector-v0.1.0-alpha.1-macos-universal.tar.gz.sha256
```

The archive contains the renamed collector executable, GPL-3.0 license,
`collector/README.md`, and changelog. The graph, viewer, cve-scan, Red, Blue,
and shared Swift package are available in the source repository.

The build script does not sign or notarize the binary. State that limitation
on any uploaded alpha release.

## Prepare release notes

Start with the matching [changelog entry](../CHANGELOG.md). Describe what is
included, the supported platforms and toolchains, compatibility limitations,
and how to handle sensitive output. List the checks that passed and any that
remain unrun. Include the archive's SHA-256 checksum.

## Publish

After maintainer approval:

1. Review the changes, set the release date in `CHANGELOG.md` and
   `CITATION.cff`, and update `SECURITY.md` if version support has changed.
2. Commit the release contents and run the checks against that commit,
   including the clean-checkout release check.
3. Build and inspect the collector archive and checksum from that commit.
4. Create the annotated tag `v0.1.0-alpha.1` and a GitHub prerelease from it.
5. Upload the verified archive and checksum.
6. Check the tag, downloadable files, rendered documentation, links, and Pages
   demo on GitHub.

Building an archive or passing a check does not publish it.
