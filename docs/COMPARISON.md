# Technical comparison

Rootstock Core and BloodHound both use graph relationships and Cypher queries
for security analysis, but they collect and model different environments. This
comparison explains scope only. It does not claim feature, maturity, or data
model parity.

| Area | Rootstock Core | BloodHound |
|---|---|---|
| Primary scope | Local macOS security boundaries | Active Directory and related identity environments |
| Collection unit | One macOS endpoint per collector run | Directory and identity data through BloodHound collectors |
| Core examples | Applications, TCC grants, entitlements, code signing, XPC, persistence | Users, groups, computers, sessions, and access-control relationships |
| Analysis | Neo4j 5.x, Cypher library, reports, and local viewer | BloodHound's documented graph and query surfaces |
| Interchange | Rootstock OpenGraph export and component-specific family import | BloodHound OpenGraph where supported by the selected edition and version |

Rootstock's collector reads local macOS files and APIs and does not perform
remote directory collection. Its optional cve-scan module has a separate,
explicitly scoped network boundary. Rootstock's Active Directory and Kerberos
surfaces add host evidence, but they do not turn the collector into an
alternative to BloodHound data collection.

Rootstock OpenGraph output is an interchange artifact. It does not establish
that Rootstock and BloodHound schemas can be merged without a mapping and
version review.

## License scopes

- Rootstock Core uses GPL-3.0 under the root `LICENSE`.
- cve-scan uses MIT under `modules/cve-scan/LICENSE`.
- Rootstock Red and Rootstock Blue use Apache-2.0 under their own license files.
- `packages/RootstockMacFacts` uses Apache-2.0 under its own license file.

Use [FAMILY.md](FAMILY.md) for Rootstock's own component and artifact
boundaries. Consult the current BloodHound project documentation for its
supported collectors, editions, schema, and licensing.
