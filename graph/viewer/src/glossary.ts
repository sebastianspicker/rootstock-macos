/** Plain-language descriptions of node and relationship kinds, shown in the inspector. */

const NODE_KINDS: Record<string, string> = {
  rs_Application:
    "An installed app bundle. Its code-signing flags, entitlements and privacy grants decide how easily code can be loaded into it and what that code gains.",
  rs_TCCPermission:
    "A macOS privacy permission (TCC service) such as Full Disk Access or Accessibility. Apps reach it through HAS_TCC_GRANT edges; only allowed grants are exposure.",
  rs_Entitlement:
    "A capability key in an app's code signature. Private Apple entitlements and the cs.* hardening exceptions matter most.",
  rs_XPCService:
    "A launchd job that registers Mach services other processes can call. Services without client checks can be driven by any local code.",
  rs_LaunchItem:
    "A persistence mechanism: LaunchDaemon, LaunchAgent, login item or cron job. It runs the listed program automatically, as the listed user.",
  rs_KeychainItem:
    "Metadata of a keychain item (never its secret). Apps listed as trusted read it without a prompt.",
  rs_MDMProfile:
    "A device-management configuration profile. Its PPPC payloads pre-approve privacy permissions for apps.",
  rs_User:
    "A local or directory account. Edges show group membership, sessions, sudo rules and what the account can write.",
  rs_LocalGroup:
    "A local group. admin and wheel members can escalate; com.apple.access_* groups gate remote access services.",
  rs_RemoteAccess:
    "A remote access service (Remote Login/SSH or Screen Sharing) and whether it is enabled.",
  rs_Firewall:
    "The macOS application firewall policy: enabled, stealth mode and the automatic-allow rules.",
  rs_LoginSession: "A login session active when the scan ran.",
  rs_AuthRight: "An authorization database right and the rule that grants it.",
  rs_AuthPlugin:
    "A third-party authorization plugin that runs inside the login and authentication flow.",
  rs_SystemExt:
    "A system extension (network, endpoint security or driver) and whether it is enabled.",
  rs_SudoersRule: "A sudoers entry. NOPASSWD rules grant root without a password.",
  rs_CriticalFile:
    "A security-sensitive file or directory with its owner, mode and ACL. Only write access beyond the expected owner is a finding.",
  rs_Computer:
    "The scanned Mac: version, posture settings, collection coverage and the host-level findings.",
  rs_CertAuthority: "A certificate authority in an app's signing chain.",
  rs_BluetoothDevice: "A paired Bluetooth device.",
  rs_KerberosArtifact: "A Kerberos ticket cache, keytab or configuration file found on the host.",
  rs_ADGroup: "An Active Directory group mapped to a local group.",
  rs_ADUser: "An Active Directory account seen on this host.",
  rs_Vulnerability:
    "A published CVE with CVSS, EPSS and KEV data, from Rootstock's curated catalogue (source registry) or from NVD (source nvd). AFFECTED_BY edges are version matches; HAS_CVE_CONTEXT edges are background for a technique class.",
  rs_AttackTechnique: "A MITRE ATT&CK technique.",
  rs_ThreatGroup: "A threat group from MITRE ATT&CK and the techniques it is documented to use.",
  rs_CWE: "A weakness class (CWE) referenced by one or more CVEs.",
  rs_SandboxProfile:
    "The App Sandbox profile derived from an app's entitlements: file, network, Mach and IOKit exceptions.",
  rs_Recommendation:
    "An action for the person who administers this Mac, with its priority and the technique it mitigates.",
  rs_Process:
    "A program that was running when the scan was taken (pid, parent pid, user, command). Flagged when it runs from a temporary folder, /Users/Shared or a user's Library, Downloads, Desktop or Documents.",
  rs_NetworkListener:
    "A TCP or UDP socket waiting for connections. Exposed when bound to a non-loopback address; reachable without firewall when exposed and the application firewall is off.",
  rs_TrustedCertificate:
    "A certificate a user or administrator added to macOS trust settings. A custom root can sign certificates for any website.",
  rs_BrowserExtension:
    "An extension installed in a browser profile, with its permissions, site access and where it was installed from (store, unpacked, external, policy).",
  rs_InstalledPackage:
    "An installer package receipt from /var/db/receipts: id, version, install date and the process that installed it.",
  rs_CveHost: "A host recorded by the cve-scan module, with the services found on it.",
  rs_CveService: "A network service the cve-scan module found on a host.",
  rs_CveWebApp: "A web application the cve-scan module found behind a service.",
  rs_CvePackage: "A software package (name and version) the cve-scan module inventoried.",
  rs_CveRepository: "A source repository the cve-scan module inventoried.",
  rs_CveManifest: "A dependency manifest inside a repository.",
  rs_CveFinding: "A vulnerability finding reported by the cve-scan module for an asset.",
  rs_Protection: "A protective control recorded for an asset by the cve-scan module.",
  rs_CveCertificate: "A TLS certificate the cve-scan module saw on a service.",
  rs_CveRemediation: "A remediation step the cve-scan module suggests for a finding.",
  rs_CveCoverageGap:
    "Something the cve-scan module could not check. A gap is not a negative finding.",
  rs_CveAsset: "An asset in the cve-scan inventory.",
  rs_CveAssetContext: "Business context recorded for an asset (criticality, environment).",
  rs_CveOwner: "The person or team recorded as owning an asset.",
  rs_CveIdentityContext: "Identity context recorded for an asset (accounts, roles).",
  rs_CveDataContext: "Data context recorded for an asset (the kind of data it holds).",
  rs_RedFinding: "A finding from a rootstock-red engagement, imported for context.",
  rs_BlueFinding: "A finding from a rootstock-blue acquisition, imported for context.",
  rs_FamilyHost: "A host referenced by rootstock-red or rootstock-blue findings.",
};

const EDGE_KINDS: Record<string, string> = {
  rs_HasTCCGrant:
    "The app holds this privacy permission; the `allowed` flag says whether the grant is active.",
  rs_HasEntitlement: "The app's signature declares this entitlement.",
  rs_CanInjectInto:
    "Modeled: local attacker code could be loaded into the app because a hardening control is missing.",
  rs_ChildInheritsTCC:
    "Modeled: an Electron app whose RunAsNode fuse is enabled lends its privacy permissions to any process that sets ELECTRON_RUN_AS_NODE.",
  rs_CanSendAppleEvent:
    "Modeled: an app with the Automation permission may script this app and borrow its capabilities.",
  rs_CommunicatesWith: "The app names one of this service's Mach ports in its entitlements.",
  rs_PersistsVia: "The launch item starts this app's code automatically.",
  rs_RunsAs: "The launch item runs under this account.",
  rs_CanReadKeychain:
    "The keychain item lists this app as trusted, so it reads the item without a prompt.",
  rs_Configures: "The MDM profile pre-approves this permission for the bundle id on the edge.",
  rs_SameTeam: "Both apps are signed by the same Developer ID team.",
  rs_MemberOf: "The account is a member of the group.",
  rs_AccessibleBy: "Members of the gating group may use this remote access service.",
  rs_HasFirewallRule:
    "The firewall has an explicit rule for this app; `allow_incoming` says which way.",
  rs_CanHijack:
    "Modeled: the account can replace this daemon's program because the binary is writable.",
  rs_TransitiveFDA: "Modeled: Automation permission over Finder gives indirect Full Disk Access.",
  rs_HasSession: "The account had this login session during the scan.",
  rs_SudoNopasswd: "The account may run this sudoers command as root without a password.",
  rs_MdmOvergrant: "Modeled: the profile grants a privacy permission to a scripting interpreter.",
  rs_SharesKeychainGroup:
    "Modeled: both apps share a keychain access group and can read each other's items.",
  rs_CanWrite:
    "Modeled: the account can write this file (world, group, ACL or unexpected-owner access).",
  rs_Protects: "Modeled: this file stores or protects the resource.",
  rs_CanModifyTCC:
    "Modeled: write access to a TCC database would let the account grant itself this permission.",
  rs_CanInjectShell:
    "Modeled: the account can write a shell start-up file that runs in every new session.",
  rs_InstalledOn: "The app was found on this host.",
  rs_LocalTo: "The account exists on this host.",
  rs_CanControlViaA11Y:
    "Modeled: an injectable app with Accessibility can drive this app's interface.",
  rs_CanBlindMonitoring:
    "Modeled: code injected into this Endpoint Security client could disable monitoring.",
  rs_CanDebug: "Modeled: members of _developer can attach a debugger to this app.",
  rs_SignedByCA: "The app's signing certificate chains to this authority.",
  rs_IssuedBy: "This authority issued the next certificate in the chain.",
  rs_PairedWith: "The Bluetooth device is paired with this host.",
  rs_CanChangePassword:
    "Modeled: an admin or passwordless-sudo account can reset this account's password.",
  rs_MappedTo: "The directory group maps onto this local group.",
  rs_ADUserOf: "The account comes from this directory domain.",
  rs_FoundOn: "The Kerberos artifact was found on this host.",
  rs_HasKerberosCache: "The account owns this Kerberos ticket cache.",
  rs_HasKeytab: "The host holds this keytab.",
  rs_CanReadKerberos: "Modeled: code in this app could read the Kerberos artifact.",
  rs_AffectedBy:
    "The installed version falls inside this CVE's affected range. This is a published weakness in that version, not evidence of exploitation.",
  rs_HasCVECandidate:
    "Candidate only: NVD evidence has unresolved conditions or an outdated, incomplete, or legacy cache. Review its match criteria and provenance; it does not contribute to CVE risk scoring.",
  rs_HasCVEContext:
    "Background only: this CVE illustrates the technique class the app is exposed to. It does not mean the app carries the CVE.",
  rs_MapsToTechnique: "The CVE exemplifies this ATT&CK technique.",
  rs_HasSandboxProfile: "The app runs under this sandbox profile.",
  rs_CanEscapeSandbox:
    "Modeled: the sandbox profile's broad exceptions plus injectability weaken the sandbox.",
  rs_CanAccessMachService: "The sandbox profile allows a lookup of this Mach service.",
  rs_BypassedGatekeeper:
    "Observed: the app is not notarized and has no quarantine record, so Gatekeeper never assessed it.",
  rs_SameIdentity: "The local account and the directory account are the same person.",
  rs_ADMemberOf: "The directory account is a member of the directory group.",
  rs_UsesTechnique: "The threat group is documented to use this technique.",
  rs_HasCWE: "The CVE is classified under this weakness.",
  rs_HasRecommendation: "This recommendation applies to the node.",
  rs_Mitigates: "Following the recommendation reduces exposure to this technique.",
  rs_InstanceOf: "This process is a running copy of that application.",
  rs_ParentOf: "This process started that process.",
  rs_RunsOn: "This process was running on that Mac.",
  rs_ListensOn: "This process or app owns that listening socket.",
  rs_ExposedOn: "This listening socket is open on that Mac.",
  rs_TrustsCertificate: "This Mac trusts that certificate through user or admin trust settings.",
  rs_SameCertificate:
    "This trusted certificate is the same certificate (same SHA-256) as one in an app's signing chain.",
  rs_HasExtension: "This browser has that extension installed.",
  rs_InstalledBy: "This application was installed by that installer package.",
  rs_HasLaunchItem: "The host has this launch item.",
  rs_HasProtection: "The asset has this protective control.",
  rs_CveAffects: "The vulnerability affects this asset in the cve-scan inventory.",
  rs_CveContainsManifest: "The repository contains this dependency manifest.",
  rs_CveDeclaresPackage: "The manifest declares this package.",
  rs_CveDependsOn: "The repository or package depends on this package.",
  rs_CveExposes: "The host exposes this service.",
  rs_CveHasCert: "The service presents this certificate.",
  rs_CveHasCoverageGap: "The asset has this coverage gap; something could not be checked.",
  rs_CveHasContext: "The asset carries this business context.",
  rs_CveHasDataContext: "The asset carries this data context.",
  rs_CveHasFinding: "The asset has this cve-scan finding.",
  rs_CveHasIdentityContext: "The asset carries this identity context.",
  rs_CveHasRemediation: "The finding has this remediation step.",
  rs_CveHosts: "The service hosts this web application.",
  rs_CveMatchedBy: "The asset version matches this vulnerability.",
  rs_CveOwnedBy: "The asset context names this owner.",
  rs_CveRun: "The host runs this package.",
  rs_CveServes: "The host serves this web application.",
  rs_RedHasFinding: "The host has this rootstock-red finding.",
  rs_BlueHasFinding: "The host has this rootstock-blue finding.",
};

/** AFFECTED_BY says how the version was matched: a curated registry range or an NVD CPE lookup. */
const MATCH_TIERS: Record<string, string> = {
  precise: "Registry match: a precise version range from Rootstock's curated catalogue.",
  cpe: "NVD match: NVD lists this CVE for the CPE of the installed version.",
};

const EDGE_CLAUSES: [string, (value: string) => string][] = [
  ["method", (value) => `Method: ${value}.`],
  ["reason", (value) => `Reason: ${value}.`],
  ["match", (value) => `Matched by ${value}.`],
  ["via", (value) => `Via ${value}.`],
  ["match_category", (value) => `Match category: ${value}.`],
  [
    "match_tier",
    (value) =>
      Object.hasOwn(MATCH_TIERS, value) ? (MATCH_TIERS[value] ?? "") : `Match tier: ${value}.`,
  ],
  ["cpe", (value) => `CPE: ${value}.`],
];

export const nodeKindKeys: string[] = Object.keys(NODE_KINDS);
export const edgeKindKeys: string[] = Object.keys(EDGE_KINDS);

export function nodeKindDescription(kind: string): string {
  return Object.hasOwn(NODE_KINDS, kind) ? (NODE_KINDS[kind] ?? "") : "";
}

function clauseText(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.filter((item) => typeof item === "string").join(", ");
  return "";
}

export function edgeKindDescription(kind: string, properties?: Record<string, unknown>): string {
  const base = Object.hasOwn(EDGE_KINDS, kind) ? (EDGE_KINDS[kind] ?? "") : "";
  const clauses = EDGE_CLAUSES.flatMap(([key, format]) => {
    const text = clauseText(properties?.[key]);
    return text ? [format(text)] : [];
  });
  return [base, ...clauses].filter(Boolean).join(" ");
}
