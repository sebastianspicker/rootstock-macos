# Threat model

This page describes what Rootstock trusts, what data it produces, and where
its protections stop. The products run separately and have different risks.

## Assumptions

1. The operator owns the analyzed systems or has explicit authorization.
2. Local collection runs on a cooperative macOS endpoint. The tools do not
   bypass System Integrity Protection, Gatekeeper, or Full Disk Access.
3. Neo4j, output directories, and case storage are under the operator's control.
4. A scan or case is a point-in-time artifact. Host state can change after it
   is collected.
5. Findings and inferred paths require analyst validation. They are not proof
   that exploitation occurred or will succeed.

## What each component can change

| Component | Default network behavior | Local changes |
|---|---|---|
| Core collector | No collection-side network path | Reads host metadata and writes the requested scan artifact |
| Core graph and API | Connects to configured Neo4j; API is restricted to loopback in this alpha | Writes graph data, reports, and viewer artifacts |
| cve-scan | Network collection and feed refresh require explicit scope or flags | Writes run artifacts and caches; does not modify scanned services |
| Rootstock Red assessment | No current network client; `--allow-network` is an policy flag for future or registered network modules | Reads posture and writes findings, state, and audit artifacts |
| Rootstock Red Lab | Network disabled in the current lab context | Separate executable; defaults to dry-run and can create or remove documented state after operator self-attestation and non-dry-run selection |
| Rootstock Blue | Offline case analysis by default | Writes case packages, timelines, detections, custody records, and reports; selected live posture commands read the running host |

Rootstock Blue ships no Endpoint Security client, subscription path, system
extension, or blocking mode. Its event-session API accepts synthetic fixtures;
its separate posture commands perform documented read-only local probes.

## Sensitive data

Real output can expose security-relevant host and organization data:

- Core scans and graph exports can identify applications, users, groups,
  entitlements, TCC grants, persistence, services, and modeled paths.
- cve-scan output can contain package versions, URLs, service banners, TLS
  metadata, scope ownership, and remediation state.
- Red output can contain host posture, paths, finding evidence, scope and
  operator identifiers, and assessment audit records.
- Blue cases can contain copied or parsed forensic artifacts, event timelines,
  file metadata, custody records, and detection evidence.

Treat real scans, exports, reports, case packages, findings, screenshots,
tokens, local Neo4j volumes, and browser query history as confidential. They
must not be committed to the public repository.

Collectors are not intended to export passwords, private keys, Keychain secret
values, session tokens, or recovery keys. Metadata and presence indicators can
still be sensitive.

Scope YAML, detection content, imported artifacts, feed mirrors, environment
files, and external sidecar executables are trusted inputs. In particular,
cve-scan credential commands and the configured Blue unified-log sidecar can
execute another program with the current process privileges. Review these inputs
as code before use. See [Configuration](CONFIGURATION.md).

## API and database access

- The bundled Neo4j Compose configuration binds Browser and Bolt to loopback
  and requires authentication.
- Every `/api/*` route requires a bearer token of at least 32 bytes.
- The same token authorizes graph reads and the implemented owned-marker and
  tier-classification state changes. It is not a read-only credential.
- API read routes use a distinct `NEO4J_READ_USER` principal. That principal
  must receive only Neo4j `MATCH` and `SHOW` privileges, never `WRITE` or
  `DBMS`; API mutation routes continue to use the writer principal.
- The alpha API refuses non-loopback listen addresses and non-loopback Neo4j
  URIs. There is no command-line override.
- The viewer fetches live graph data through the authenticated API. The `/`
  document does not embed the graph.

Do not expose these services through a proxy, tunnel, or broader interface for
real data without a separate access-control and deployment review.

## Technical limitations

- Missing Full Disk Access can make TCC and other protected evidence incomplete.
- Apple changes schemas and security behavior between macOS releases. Unknown
  versions can produce partial modeling until support is added and tested.
- Code-signing and entitlement relationships are necessary-condition models.
  Runtime defenses and application behavior can prevent a modeled path.
- Keychain access depends on lock state, user authentication, ACL evaluation,
  and signature checks that are not fully represented in the graph.
- Blue offline analysis cannot decrypt FileVault media without valid operator-
  supplied access material and does not extract Secure Enclave secrets or full
  physical memory from Apple silicon.
- The repository does not provide real-time fleet monitoring, a multi-platform
  endpoint monitor, a SIEM, an MDM system, or automated incident containment.

## Using and sharing results

Run collection and Red Lab actions only within written authorization. Review
outputs before sharing them. If a result indicates a third-party vulnerability,
use the affected project's private reporting process before public disclosure.

Repository vulnerabilities must be reported through [SECURITY.md](../SECURITY.md).
Rootstock Red's additional operating policy is in
[ACCEPTABLE_USE.md](../rootstock-red/ACCEPTABLE_USE.md).
