"""OpenGraph type and display metadata for host-evidence labels (processes, listeners, inventory)."""

from __future__ import annotations

HOST_EVIDENCE_NODE_TYPES: dict[str, dict] = {
    "Process": {"kind": "rs_Process", "icon": "fa-gears", "color": "#9e86ff"},
    "NetworkListener": {
        "kind": "rs_NetworkListener",
        "icon": "fa-ethernet",
        "color": "#ec6cb9",
    },
    "TrustedCertificate": {
        "kind": "rs_TrustedCertificate",
        "icon": "fa-certificate",
        "color": "#f2a93b",
    },
    "BrowserExtension": {
        "kind": "rs_BrowserExtension",
        "icon": "fa-puzzle-piece",
        "color": "#4ac1a2",
    },
    "InstalledPackage": {
        "kind": "rs_InstalledPackage",
        "icon": "fa-box-archive",
        "color": "#a8b1ff",
    },
}

# Host evidence edges are facts about the scanned Mac, not attack steps.
HOST_EVIDENCE_EDGE_TYPES: dict[str, dict] = {
    "INSTANCE_OF": {"kind": "rs_InstanceOf", "traversable": False},
    "PARENT_OF": {"kind": "rs_ParentOf", "traversable": False},
    "RUNS_ON": {"kind": "rs_RunsOn", "traversable": False},
    "LISTENS_ON": {"kind": "rs_ListensOn", "traversable": False},
    "EXPOSED_ON": {"kind": "rs_ExposedOn", "traversable": False},
    "TRUSTS_CERTIFICATE": {"kind": "rs_TrustsCertificate", "traversable": False},
    "SAME_CERTIFICATE": {"kind": "rs_SameCertificate", "traversable": False},
    "HAS_EXTENSION": {"kind": "rs_HasExtension", "traversable": False},
    "INSTALLED_BY": {"kind": "rs_InstalledBy", "traversable": False},
}

HOST_EVIDENCE_DISPLAY_FIELDS: dict[str, tuple[tuple[str, ...], str]] = {
    "Process": (("command", "process_key"), "Process"),
    "NetworkListener": (("endpoint", "listener_key"), "Network Listener"),
    "TrustedCertificate": (("subject", "sha256"), "Trusted Certificate"),
    "BrowserExtension": (("name", "extension_id"), "Browser Extension"),
    "InstalledPackage": (("package_id", "package_key"), "Installed Package"),
}
