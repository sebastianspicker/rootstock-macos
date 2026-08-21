"""Pure OpenGraph type, identity, property, and edge mapping helpers."""

from __future__ import annotations

from constants import NODE_KEY_PROPERTY

# ── Node type mapping ───────────────────────────────────────────────────────

# Node colors optimized for dark backgrounds with high distinguishability.
# Each category uses a distinct hue to aid rapid visual identification:
#   Blue spectrum  = infrastructure (apps, computers, services)
#   Red spectrum   = threats & vulnerabilities
#   Green spectrum = services & sessions
#   Yellow/Orange  = persistence & escalation
#   Purple         = identity & certificates
#   Teal/Cyan      = security controls
NODE_TYPE_MAP: dict[str, dict] = {
    "Application": {"kind": "rs_Application", "icon": "fa-apple", "color": "#58a6ff"},
    "TCC_Permission": {
        "kind": "rs_TCCPermission",
        "icon": "fa-shield-halved",
        "color": "#f47067",
    },
    "Entitlement": {"kind": "rs_Entitlement", "icon": "fa-key", "color": "#e3b341"},
    "XPC_Service": {"kind": "rs_XPCService", "icon": "fa-plug", "color": "#56d364"},
    "LaunchItem": {"kind": "rs_LaunchItem", "icon": "fa-clock", "color": "#d29922"},
    "Keychain_Item": {"kind": "rs_KeychainItem", "icon": "fa-lock", "color": "#bc8cff"},
    "MDM_Profile": {"kind": "rs_MDMProfile", "icon": "fa-building", "color": "#8b949e"},
    "User": {"kind": "rs_User", "icon": "fa-user", "color": "#c9d1d9"},
    "LocalGroup": {"kind": "rs_LocalGroup", "icon": "fa-users", "color": "#79c0ff"},
    "RemoteAccessService": {
        "kind": "rs_RemoteAccess",
        "icon": "fa-network-wired",
        "color": "#ffa657",
    },
    "FirewallPolicy": {"kind": "rs_Firewall", "icon": "fa-fire", "color": "#db6d28"},
    "LoginSession": {
        "kind": "rs_LoginSession",
        "icon": "fa-right-to-bracket",
        "color": "#7ee787",
    },
    "AuthorizationRight": {
        "kind": "rs_AuthRight",
        "icon": "fa-gavel",
        "color": "#ff7b72",
    },
    "AuthorizationPlugin": {
        "kind": "rs_AuthPlugin",
        "icon": "fa-puzzle-piece",
        "color": "#c297eb",
    },
    "SystemExtension": {
        "kind": "rs_SystemExt",
        "icon": "fa-microchip",
        "color": "#a5d6ff",
    },
    "SudoersRule": {
        "kind": "rs_SudoersRule",
        "icon": "fa-terminal",
        "color": "#ffa198",
    },
    "CriticalFile": {
        "kind": "rs_CriticalFile",
        "icon": "fa-file-shield",
        "color": "#f778ba",
    },
    "Computer": {"kind": "rs_Computer", "icon": "fa-laptop", "color": "#6cb6ff"},
    "CertificateAuthority": {
        "kind": "rs_CertAuthority",
        "icon": "fa-certificate",
        "color": "#d2a8ff",
    },
    "BluetoothDevice": {
        "kind": "rs_BluetoothDevice",
        "icon": "fa-bluetooth-b",
        "color": "#1f6feb",
    },
    "KerberosArtifact": {
        "kind": "rs_KerberosArtifact",
        "icon": "fa-ticket",
        "color": "#ea6045",
    },
    "ADGroup": {"kind": "rs_ADGroup", "icon": "fa-sitemap", "color": "#388bfd"},
    "Vulnerability": {"kind": "rs_Vulnerability", "icon": "fa-bug", "color": "#f85149"},
    "AttackTechnique": {
        "kind": "rs_AttackTechnique",
        "icon": "fa-crosshairs",
        "color": "#da3633",
    },
    "SandboxProfile": {
        "kind": "rs_SandboxProfile",
        "icon": "fa-box",
        "color": "#2ea043",
    },
    "ADUser": {"kind": "rs_ADUser", "icon": "fa-user-shield", "color": "#388bfd"},
    "ThreatGroup": {
        "kind": "rs_ThreatGroup",
        "icon": "fa-skull-crossbones",
        "color": "#b62324",
    },
    "CWE": {"kind": "rs_CWE", "icon": "fa-triangle-exclamation", "color": "#e09b13"},
    "Recommendation": {
        "kind": "rs_Recommendation",
        "icon": "fa-lightbulb",
        "color": "#3fb950",
    },
    "Host": {"kind": "rs_CveHost", "icon": "fa-server", "color": "#39c5cf"},
    "Service": {
        "kind": "rs_CveService",
        "icon": "fa-network-wired",
        "color": "#f2cc60",
    },
    "WebApp": {"kind": "rs_CveWebApp", "icon": "fa-globe", "color": "#3fb950"},
    "Package": {"kind": "rs_CvePackage", "icon": "fa-box-open", "color": "#d2a8ff"},
    "Repository": {
        "kind": "rs_CveRepository",
        "icon": "fa-code-branch",
        "color": "#a371f7",
    },
    "Manifest": {"kind": "rs_CveManifest", "icon": "fa-file-code", "color": "#bc8cff"},
    "Finding": {
        "kind": "rs_CveFinding",
        "icon": "fa-magnifying-glass-chart",
        "color": "#ff7b72",
    },
    "Protection": {
        "kind": "rs_Protection",
        "icon": "fa-shield",
        "color": "#3fb950",
    },
    "Certificate": {
        "kind": "rs_CveCertificate",
        "icon": "fa-certificate",
        "color": "#76e3ea",
    },
    "Remediation": {
        "kind": "rs_CveRemediation",
        "icon": "fa-screwdriver-wrench",
        "color": "#56d364",
    },
    "CoverageGap": {
        "kind": "rs_CveCoverageGap",
        "icon": "fa-circle-question",
        "color": "#ffa657",
    },
    "Asset": {"kind": "rs_CveAsset", "icon": "fa-diamond", "color": "#8b949e"},
    "AssetContext": {
        "kind": "rs_CveAssetContext",
        "icon": "fa-tags",
        "color": "#79c0ff",
    },
    "Owner": {"kind": "rs_CveOwner", "icon": "fa-user-tie", "color": "#c9d1d9"},
    "IdentityContext": {
        "kind": "rs_CveIdentityContext",
        "icon": "fa-id-card",
        "color": "#ffab70",
    },
    "DataContext": {
        "kind": "rs_CveDataContext",
        "icon": "fa-database",
        "color": "#f778ba",
    },
}

# Family open-export (rootstock-red / rootstock-blue) disambiguates labels that
# are shared with cve-scan (Finding, Host) so the canvas legend stays honest.
FAMILY_FINDING_TYPE: dict[str, dict] = {
    "rootstock-red": {
        "kind": "rs_RedFinding",
        "icon": "fa-user-secret",
        "color": "#e05260",
    },
    "rootstock-blue": {
        "kind": "rs_BlueFinding",
        "icon": "fa-shield-halved",
        "color": "#58a6ff",
    },
}

FAMILY_HOST_TYPE: dict = {
    "kind": "rs_FamilyHost",
    "icon": "fa-laptop",
    "color": "#39c5cf",
}

FAMILY_HAS_FINDING_TYPE: dict[str, dict] = {
    "rootstock-red": {"kind": "rs_RedHasFinding", "traversable": False},
    "rootstock-blue": {"kind": "rs_BlueHasFinding", "traversable": False},
}

# ── Edge type mapping ───────────────────────────────────────────────────────

EDGE_TYPE_MAP: dict[str, dict] = {
    "HAS_TCC_GRANT": {"kind": "rs_HasTCCGrant", "traversable": True},
    "HAS_ENTITLEMENT": {"kind": "rs_HasEntitlement", "traversable": False},
    "CAN_INJECT_INTO": {"kind": "rs_CanInjectInto", "traversable": True},
    "CHILD_INHERITS_TCC": {"kind": "rs_ChildInheritsTCC", "traversable": True},
    "CAN_SEND_APPLE_EVENT": {"kind": "rs_CanSendAppleEvent", "traversable": True},
    "COMMUNICATES_WITH": {"kind": "rs_CommunicatesWith", "traversable": True},
    "PERSISTS_VIA": {"kind": "rs_PersistsVia", "traversable": True},
    "RUNS_AS": {"kind": "rs_RunsAs", "traversable": False},
    "CAN_READ_KEYCHAIN": {"kind": "rs_CanReadKeychain", "traversable": True},
    "CONFIGURES": {"kind": "rs_Configures", "traversable": False},
    "SIGNED_BY_SAME_TEAM": {"kind": "rs_SameTeam", "traversable": False},
    "MEMBER_OF": {"kind": "rs_MemberOf", "traversable": False},
    "ACCESSIBLE_BY": {"kind": "rs_AccessibleBy", "traversable": True},
    "HAS_FIREWALL_RULE": {"kind": "rs_HasFirewallRule", "traversable": False},
    "CAN_HIJACK": {"kind": "rs_CanHijack", "traversable": True},
    "HAS_TRANSITIVE_FDA": {"kind": "rs_TransitiveFDA", "traversable": True},
    "HAS_SESSION": {"kind": "rs_HasSession", "traversable": False},
    "SUDO_NOPASSWD": {"kind": "rs_SudoNopasswd", "traversable": True},
    "MDM_OVERGRANT": {"kind": "rs_MdmOvergrant", "traversable": True},
    "SHARES_KEYCHAIN_GROUP": {"kind": "rs_SharesKeychainGroup", "traversable": False},
    "CAN_WRITE": {"kind": "rs_CanWrite", "traversable": True},
    "PROTECTS": {"kind": "rs_Protects", "traversable": False},
    "CAN_MODIFY_TCC": {"kind": "rs_CanModifyTCC", "traversable": True},
    "CAN_INJECT_SHELL": {"kind": "rs_CanInjectShell", "traversable": True},
    "INSTALLED_ON": {"kind": "rs_InstalledOn", "traversable": False},
    "LOCAL_TO": {"kind": "rs_LocalTo", "traversable": False},
    "CAN_CONTROL_VIA_A11Y": {"kind": "rs_CanControlViaA11Y", "traversable": True},
    "CAN_BLIND_MONITORING": {"kind": "rs_CanBlindMonitoring", "traversable": True},
    "CAN_DEBUG": {"kind": "rs_CanDebug", "traversable": True},
    "SIGNED_BY_CA": {"kind": "rs_SignedByCA", "traversable": False},
    "ISSUED_BY": {"kind": "rs_IssuedBy", "traversable": False},
    "PAIRED_WITH": {"kind": "rs_PairedWith", "traversable": False},
    "CAN_CHANGE_PASSWORD": {"kind": "rs_CanChangePassword", "traversable": True},
    "MAPPED_TO": {"kind": "rs_MappedTo", "traversable": False},
    "AD_USER_OF": {"kind": "rs_ADUserOf", "traversable": False},
    "FOUND_ON": {"kind": "rs_FoundOn", "traversable": False},
    "HAS_KERBEROS_CACHE": {"kind": "rs_HasKerberosCache", "traversable": True},
    "HAS_KEYTAB": {"kind": "rs_HasKeytab", "traversable": False},
    "CAN_READ_KERBEROS": {"kind": "rs_CanReadKerberos", "traversable": True},
    "AFFECTED_BY": {"kind": "rs_AffectedBy", "traversable": True},
    "MAPS_TO_TECHNIQUE": {"kind": "rs_MapsToTechnique", "traversable": False},
    "HAS_SANDBOX_PROFILE": {"kind": "rs_HasSandboxProfile", "traversable": False},
    "CAN_ESCAPE_SANDBOX": {"kind": "rs_CanEscapeSandbox", "traversable": True},
    "CAN_ACCESS_MACH_SERVICE": {"kind": "rs_CanAccessMachService", "traversable": True},
    "BYPASSED_GATEKEEPER": {"kind": "rs_BypassedGatekeeper", "traversable": True},
    "SAME_IDENTITY": {"kind": "rs_SameIdentity", "traversable": True},
    "AD_MEMBER_OF": {"kind": "rs_ADMemberOf", "traversable": True},
    "USES_TECHNIQUE": {"kind": "rs_UsesTechnique", "traversable": False},
    "HAS_CWE": {"kind": "rs_HasCWE", "traversable": False},
    "HAS_RECOMMENDATION": {"kind": "rs_HasRecommendation", "traversable": False},
    "MITIGATES": {"kind": "rs_Mitigates", "traversable": False},
    "AFFECTS": {"kind": "rs_CveAffects", "traversable": True},
    "CONTAINS_MANIFEST": {"kind": "rs_CveContainsManifest", "traversable": False},
    "DECLARES_PACKAGE": {"kind": "rs_CveDeclaresPackage", "traversable": False},
    "DEPENDS_ON": {"kind": "rs_CveDependsOn", "traversable": True},
    "EXPOSES": {"kind": "rs_CveExposes", "traversable": True},
    "HAS_CERT": {"kind": "rs_CveHasCert", "traversable": False},
    "HAS_COVERAGE_GAP": {"kind": "rs_CveHasCoverageGap", "traversable": False},
    "HAS_CONTEXT": {"kind": "rs_CveHasContext", "traversable": False},
    "HAS_DATA_CONTEXT": {"kind": "rs_CveHasDataContext", "traversable": False},
    "HAS_FINDING": {"kind": "rs_CveHasFinding", "traversable": False},
    "HAS_LAUNCH_ITEM": {"kind": "rs_HasLaunchItem", "traversable": False},
    "HAS_PROTECTION": {"kind": "rs_HasProtection", "traversable": False},
    "HAS_IDENTITY_CONTEXT": {
        "kind": "rs_CveHasIdentityContext",
        "traversable": False,
    },
    "HAS_REMEDIATION": {"kind": "rs_CveHasRemediation", "traversable": False},
    "HOSTS": {"kind": "rs_CveHosts", "traversable": True},
    "MATCHED_BY": {"kind": "rs_CveMatchedBy", "traversable": False},
    "OWNED_BY": {"kind": "rs_CveOwnedBy", "traversable": False},
    "RUN": {"kind": "rs_CveRun", "traversable": True},
    "SERVES": {"kind": "rs_CveServes", "traversable": True},
}


def _truthy_family_export(props: dict | None) -> bool:
    """Return True when props mark an optional family open-export artifact."""
    if not props:
        return False
    value = props.get("family_export")
    return value is True or value == "true" or value == 1


def family_source(props: dict | None) -> str | None:
    """Return rootstock-red / rootstock-blue when props carry family provenance."""
    if not props:
        return None
    source = props.get("source")
    if source in FAMILY_FINDING_TYPE:
        return str(source)
    return None


def resolve_node_type_info(label: str, props: dict | None = None) -> dict | None:
    """Map a Neo4j label (+ optional props) to OpenGraph/viewer kind metadata.

    Family findings and hosts share labels with cve-scan. Disambiguate by
    ``family_export`` + ``source`` so red/blue are not painted as CVE findings.
    """
    props = props or {}
    if label == "Finding" and _truthy_family_export(props):
        source = family_source(props)
        if source is not None:
            return FAMILY_FINDING_TYPE[source]
    if label == "Host" and _truthy_family_export(props):
        return FAMILY_HOST_TYPE
    return NODE_TYPE_MAP.get(label)


def resolve_edge_type_info(rel_type: str, props: dict | None = None) -> dict | None:
    """Map a relationship type (+ optional props) to OpenGraph edge kind metadata."""
    props = props or {}
    if rel_type == "HAS_FINDING" and _truthy_family_export(props):
        source = family_source(props)
        if source is not None:
            return FAMILY_HAS_FINDING_TYPE[source]
    return EDGE_TYPE_MAP.get(rel_type)


def map_node_for_opengraph(hostname: str, label: str, props: dict) -> dict | None:
    """Build one OpenGraph/viewer node from a label and property dict (no Neo4j)."""
    type_info = resolve_node_type_info(label, props)
    if not type_info:
        return None
    key = _node_key(label, props)
    return {
        "id": make_node_id(hostname, label, key),
        "kind": type_info["kind"],
        "label": _node_display_name(label, props),
        "properties": {
            **_serialize_props(props),
            "_icon": type_info["icon"],
            "_color": type_info["color"],
        },
    }


def map_edge_for_opengraph(
    hostname: str,
    *,
    src_label: str,
    src_props: dict,
    tgt_label: str,
    tgt_props: dict,
    rel_type: str,
    rel_props: dict | None = None,
) -> dict | None:
    """Build one OpenGraph/viewer edge from endpoint props and relationship type."""
    rel_props = rel_props or {}
    type_info = resolve_edge_type_info(rel_type, rel_props)
    if not type_info:
        return None
    return {
        "source": make_node_id(hostname, src_label, _node_key(src_label, src_props)),
        "target": make_node_id(hostname, tgt_label, _node_key(tgt_label, tgt_props)),
        "kind": type_info["kind"],
        "properties": {
            **_serialize_props(rel_props),
            "_traversable": type_info["traversable"],
        },
    }


# ── Node ID generation ──────────────────────────────────────────────────────


def _sanitize(text: str) -> str:
    """Convert text to a safe ID component."""
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in text)


def make_node_id(hostname: str, label: str, key: str) -> str:
    """Generate a unique OpenGraph node ID."""
    return f"rs-{_sanitize(hostname)}-{_sanitize(label.lower())}-{_sanitize(key)}"


# ── Node key extraction ─────────────────────────────────────────────────────


def _node_key(label: str, props: dict) -> str:
    """Extract the unique key for a node based on its label."""
    # Keychain_Item uses a composite key not expressible as a single property name.
    if label == "Keychain_Item":
        return f"{props.get('label', '')}-{props.get('kind', '')}"
    if label == "Application":
        return str(props.get("app_key") or props.get("bundle_id", "unknown"))
    if label == "Computer":
        return str(props.get("computer_key") or props.get("hostname", "unknown"))
    if label == "SandboxProfile":
        return str(props.get("profile_key") or props.get("bundle_id", "unknown"))
    key = NODE_KEY_PROPERTY.get(label, "name")
    return str(props.get(key, "unknown"))


# ── Node properties ─────────────────────────────────────────────────────────


_NODE_DISPLAY_FIELDS: dict[str, tuple[tuple[str, ...], str]] = {
    "Application": (("name", "bundle_id"), "Unknown App"),
    "TCC_Permission": (("display_name", "service"), "Unknown Permission"),
    "Entitlement": (("name",), "Unknown Entitlement"),
    "XPC_Service": (("label",), "Unknown XPC"),
    "Keychain_Item": (("label",), "Unknown Keychain Item"),
    "Finding": (("name", "finding_id", "id"), "Finding"),
    "Host": (("hostname", "name", "id"), "Host"),
    "Protection": (("name", "id"), "Protection"),
}


def _node_display_name(label: str, props: dict) -> str:
    """Human-readable display name for a node."""
    fields, fallback = _NODE_DISPLAY_FIELDS.get(
        label,
        (("name", "display_name", "label"), "Unknown"),
    )
    return str(next((props[field] for field in fields if props.get(field)), fallback))


def _serialize_props(props: dict) -> dict:
    """Convert Neo4j node properties to JSON-serializable dict."""
    result = {}
    for k, v in props.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            result[k] = v
        elif isinstance(v, list):
            result[k] = [str(item) for item in v]
        else:
            result[k] = str(v)
    return result


def _primary_label(labels: list[str]) -> str:
    """Pick the primary label from a node's labels, preferring known labels."""
    known = set(NODE_TYPE_MAP.keys())
    for label in labels:
        if label in known:
            return label
    return labels[0] if labels else "Unknown"

