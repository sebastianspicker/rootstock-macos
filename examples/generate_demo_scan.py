#!/usr/bin/env python3
"""
generate_demo_scan.py — Build a synthetic Rootstock scan for demos and screenshots.

Constructs a complete, schema-validated scan JSON representing an "Acme Corp MacBook"
with 15 applications designed to trigger specific attack paths. Uses graph/models.py
Pydantic models so the demo data breaks loudly if the schema changes.

Usage:
    python3 examples/generate_demo_scan.py                   # → examples/demo-scan.json
    python3 examples/generate_demo_scan.py -o /tmp/scan.json # custom output
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure graph/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "graph"))

from models import (
    ADBindingData,
    ApplicationData,
    AuthorizationPluginData,
    AuthorizationRightData,
    BluetoothDeviceData,
    CertificateDetailData,
    CollectionErrorData,
    ElevationInfo,
    EntitlementData,
    FileACLData,
    FirewallAppRuleData,
    FirewallStatusData,
    KerberosArtifactData,
    KeychainItemData,
    LaunchItemData,
    LocalGroupData,
    LoginSessionData,
    MDMProfileData,
    RemoteAccessServiceData,
    RunningProcessData,
    ScanResult,
    SudoersRuleData,
    SystemExtensionData,
    TCCGrantData,
    TCCPolicyData,
    UserDetailData,
    XPCServiceData,
)

# ---------------------------------------------------------------------------
# Helper: certificate chain builder
# ---------------------------------------------------------------------------

def _apple_cert_chain(leaf_cn: str, leaf_org: str, leaf_sha_prefix: str) -> list[dict]:
    """Build a 3-level Apple Developer ID certificate chain."""
    return [
        CertificateDetailData(
            common_name=leaf_cn,
            organization=leaf_org,
            sha256=leaf_sha_prefix.ljust(64, "0"),
            valid_from="2023-06-15T00:00:00Z",
            valid_to="2028-06-15T00:00:00Z",
            is_root=False,
        ),
        CertificateDetailData(
            common_name="Developer ID Certification Authority",
            organization="Apple Inc.",
            sha256="aa11bb22cc33dd44ee55ff6600112233aa11bb22cc33dd44ee55ff6600112233",
            valid_from="2012-02-01T22:12:15Z",
            valid_to="2027-02-01T22:12:15Z",
            is_root=False,
        ),
        CertificateDetailData(
            common_name="Apple Root CA",
            organization="Apple Inc.",
            sha256="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
            valid_from="2006-04-25T21:40:36Z",
            valid_to="2035-02-09T21:40:36Z",
            is_root=True,
        ),
    ]


def _ent(name: str, category: str, *, private: bool = False, critical: bool = False) -> EntitlementData:
    return EntitlementData(name=name, is_private=private, category=category, is_security_critical=critical)


# ---------------------------------------------------------------------------
# Applications (15)
# ---------------------------------------------------------------------------

applications: list[ApplicationData] = [
    # 1. iTerm2 — injectable with FDA → "money shot" attack path
    ApplicationData(
        name="iTerm2",
        bundle_id="com.googlecode.iterm2",
        path="/Applications/iTerm.app",
        version="3.5.2",
        team_id="H7V7XYVQ7D",
        hardened_runtime=False,
        library_validation=False,
        is_electron=False,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: George Nachman (H7V7XYVQ7D)",
        signing_certificate_sha256="a1b2c3d4e5f60000000000000000000000000000000000000000000000000000",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: George Nachman (H7V7XYVQ7D)",
            "George Nachman",
            "a1b2c3d4e5f6",
        ),
        entitlements=[
            _ent("com.apple.security.cs.allow-dyld-environment-variables", "injection", critical=True),
            _ent("com.apple.security.cs.disable-library-validation", "injection", critical=True),
            _ent("com.apple.security.device.audio-input", "tcc"),
        ],
        injection_methods=["dyld_insert_via_entitlement", "missing_library_validation"],
    ),

    # 2. Slack — Electron, Camera + Mic + Screen Recording TCC
    ApplicationData(
        name="Slack",
        bundle_id="com.tinyspeck.slackmacgap",
        path="/Applications/Slack.app",
        version="4.39.96",
        team_id="BQR82RBBHL",
        hardened_runtime=False,
        library_validation=False,
        is_electron=True,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)",
        signing_certificate_sha256="b2c3d4e5f6a10000000000000000000000000000000000000000000000000000",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)",
            "Slack Technologies, Inc.",
            "b2c3d4e5f6a1",
        ),
        entitlements=[
            _ent("com.apple.security.cs.allow-dyld-environment-variables", "injection", critical=True),
            _ent("com.apple.security.network.client", "network"),
            _ent("com.apple.security.device.audio-input", "tcc"),
            _ent("com.apple.security.device.camera", "tcc"),
            _ent("com.apple.developer.icloud-container-identifiers", "icloud"),
        ],
        injection_methods=["dyld_insert_via_entitlement", "missing_library_validation", "electron_env_var"],
    ),

    # 3. VS Code — Electron, Accessibility TCC
    ApplicationData(
        name="Visual Studio Code",
        bundle_id="com.microsoft.VSCode",
        path="/Applications/Visual Studio Code.app",
        version="1.96.2",
        team_id="UBF8T346G9",
        hardened_runtime=False,
        library_validation=False,
        is_electron=True,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: Microsoft Corporation (UBF8T346G9)",
        signing_certificate_sha256="c3d4e5f6a1b20000000000000000000000000000000000000000000000000000",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: Microsoft Corporation (UBF8T346G9)",
            "Microsoft Corporation",
            "c3d4e5f6a1b2",
        ),
        entitlements=[
            _ent("com.apple.security.cs.allow-dyld-environment-variables", "injection", critical=True),
            _ent("com.apple.security.cs.disable-library-validation", "injection", critical=True),
            _ent("com.apple.security.network.client", "network"),
        ],
        injection_methods=["dyld_insert_via_entitlement", "missing_library_validation", "electron_env_var"],
    ),

    # 4. Zoom — hardened, Camera + Mic TCC, NOT injectable (safe comparison)
    ApplicationData(
        name="zoom.us",
        bundle_id="us.zoom.xos",
        path="/Applications/zoom.us.app",
        version="6.3.5",
        team_id="BJ4HAAB9B3",
        hardened_runtime=True,
        library_validation=True,
        is_electron=False,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)",
        signing_certificate_sha256="d4e5f6a1b2c30000000000000000000000000000000000000000000000000000",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)",
            "Zoom Video Communications, Inc.",
            "d4e5f6a1b2c3",
        ),
        entitlements=[
            _ent("com.apple.security.device.camera", "tcc"),
            _ent("com.apple.security.device.audio-input", "tcc"),
            _ent("com.apple.security.network.client", "network"),
        ],
        injection_methods=[],
    ),

    # 5. OmniGraffle — Apple Events TCC → transitive FDA via Finder
    ApplicationData(
        name="OmniGraffle",
        bundle_id="com.omnigroup.OmniGraffle7",
        path="/Applications/OmniGraffle.app",
        version="7.23.2",
        team_id="34YW5R9HE4",
        hardened_runtime=True,
        library_validation=False,
        is_electron=False,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: The Omni Group (34YW5R9HE4)",
        signing_certificate_sha256="e5f6a1b2c3d40000000000000000000000000000000000000000000000000000",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: The Omni Group (34YW5R9HE4)",
            "The Omni Group",
            "e5f6a1b2c3d4",
        ),
        entitlements=[
            _ent("com.apple.security.automation.apple-events", "tcc"),
            _ent("com.apple.security.network.client", "network"),
        ],
        injection_methods=["missing_library_validation"],
    ),

    # 6. Firefox — missing lib validation, no TCC grants (stepping stone)
    ApplicationData(
        name="Firefox",
        bundle_id="org.mozilla.firefox",
        path="/Applications/Firefox.app",
        version="134.0",
        team_id="43AQ936H96",
        hardened_runtime=True,
        library_validation=False,
        is_electron=False,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: Mozilla Corporation (43AQ936H96)",
        signing_certificate_sha256="f6a1b2c3d4e50000000000000000000000000000000000000000000000000000",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: Mozilla Corporation (43AQ936H96)",
            "Mozilla Corporation",
            "f6a1b2c3d4e5",
        ),
        entitlements=[
            _ent("com.apple.security.network.client", "network"),
            _ent("com.apple.security.cs.disable-library-validation", "injection", critical=True),
        ],
        injection_methods=["missing_library_validation"],
    ),

    # 7. Acme Backup — FDA via entitlement, root daemon, missing lib validation
    ApplicationData(
        name="Acme Backup",
        bundle_id="com.acmecorp.backup",
        path="/Applications/Acme Backup.app",
        version="2.1.0",
        team_id="ACME123456",
        hardened_runtime=True,
        library_validation=False,
        is_electron=False,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: Acme Corp (ACME123456)",
        signing_certificate_sha256="01020304050600000000000000000000000000000000000000000000000000ab",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: Acme Corp (ACME123456)",
            "Acme Corp",
            "0102030405060000ab",
        ),
        entitlements=[
            _ent("com.apple.private.tcc.allow", "tcc", private=True, critical=True),
            _ent("com.apple.security.cs.disable-library-validation", "injection", critical=True),
            _ent("com.apple.security.network.client", "network"),
        ],
        injection_methods=["missing_library_validation"],
    ),

    # 8. Acme VPN — system extension (network), XPC without client verification
    ApplicationData(
        name="Acme VPN",
        bundle_id="com.acmecorp.vpn",
        path="/Applications/Acme VPN.app",
        version="3.4.1",
        team_id="ACME123456",
        hardened_runtime=True,
        library_validation=True,
        is_electron=False,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: Acme Corp (ACME123456)",
        signing_certificate_sha256="02030405060100000000000000000000000000000000000000000000000000ab",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: Acme Corp (ACME123456)",
            "Acme Corp",
            "0203040506010000ab",
        ),
        entitlements=[
            _ent("com.apple.developer.networking.networkextension", "network", critical=True),
            _ent("com.apple.security.network.client", "network"),
        ],
        injection_methods=[],
    ),

    # 9. Acme Launcher — writable LaunchAgent plist
    ApplicationData(
        name="Acme Launcher",
        bundle_id="com.acmecorp.launcher",
        path="/Applications/Acme Launcher.app",
        version="1.0.3",
        team_id="ACME123456",
        hardened_runtime=True,
        library_validation=True,
        is_electron=False,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: Acme Corp (ACME123456)",
        signing_certificate_sha256="03040506010200000000000000000000000000000000000000000000000000ab",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: Acme Corp (ACME123456)",
            "Acme Corp",
            "0304050601020000ab",
        ),
        entitlements=[
            _ent("com.apple.security.network.client", "network"),
        ],
        injection_methods=[],
    ),

    # 10. Acme Analytics — ad-hoc signed, Camera TCC → unnotarized with TCC
    ApplicationData(
        name="Acme Analytics",
        bundle_id="com.acmecorp.analytics",
        path="/Applications/Acme Analytics.app",
        version="0.9.1",
        team_id=None,
        hardened_runtime=False,
        library_validation=False,
        is_electron=False,
        is_system=False,
        signed=True,
        is_adhoc_signed=True,
        is_notarized=False,
        signing_certificate_cn=None,
        signing_certificate_sha256=None,
        certificate_chain_length=0,
        certificate_chain=[],
        entitlements=[
            _ent("com.apple.security.device.camera", "tcc"),
        ],
        injection_methods=["missing_library_validation"],
    ),

    # 11. Finder — Apple system, SIP-protected, implicit FDA
    ApplicationData(
        name="Finder",
        bundle_id="com.apple.finder",
        path="/System/Library/CoreServices/Finder.app",
        version="15.3",
        team_id=None,
        hardened_runtime=True,
        library_validation=True,
        is_electron=False,
        is_system=True,
        signed=True,
        is_sip_protected=True,
        is_notarized=None,
        entitlements=[
            _ent("com.apple.private.tcc.allow", "tcc", private=True, critical=True),
            _ent("com.apple.rootless.storage.Finder", "privilege", private=True, critical=True),
        ],
        injection_methods=[],
    ),

    # 12. Terminal — Apple system, SIP-protected, not injectable
    ApplicationData(
        name="Terminal",
        bundle_id="com.apple.Terminal",
        path="/System/Applications/Utilities/Terminal.app",
        version="2.14",
        team_id=None,
        hardened_runtime=True,
        library_validation=True,
        is_electron=False,
        is_system=True,
        signed=True,
        is_sip_protected=True,
        is_notarized=None,
        entitlements=[
            _ent("com.apple.private.tcc.allow", "tcc", private=True, critical=True),
            _ent("com.apple.rootless.storage.Terminal", "privilege", private=True, critical=True),
        ],
        injection_methods=[],
    ),

    # 13. System Preferences — Apple system, SIP-protected, FDA → Tier 0
    ApplicationData(
        name="System Settings",
        bundle_id="com.apple.systempreferences",
        path="/System/Applications/System Settings.app",
        version="15.3",
        team_id=None,
        hardened_runtime=True,
        library_validation=True,
        is_electron=False,
        is_system=True,
        signed=True,
        is_sip_protected=True,
        is_notarized=None,
        entitlements=[
            _ent("com.apple.private.tcc.allow", "tcc", private=True, critical=True),
            _ent("com.apple.rootless.storage.SystemSettings", "privilege", private=True, critical=True),
        ],
        injection_methods=[],
    ),

    # 14. 1Password — Electron, Keychain ACL trust
    ApplicationData(
        name="1Password",
        bundle_id="com.1password.1password",
        path="/Applications/1Password.app",
        version="8.10.58",
        team_id="2BUA8C4S2C",
        hardened_runtime=False,
        library_validation=False,
        is_electron=True,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: AgileBits Inc. (2BUA8C4S2C)",
        signing_certificate_sha256="a1a2a3a4a5a60000000000000000000000000000000000000000000000000000",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: AgileBits Inc. (2BUA8C4S2C)",
            "AgileBits Inc.",
            "a1a2a3a4a5a6",
        ),
        entitlements=[
            _ent("com.apple.security.cs.allow-dyld-environment-variables", "injection", critical=True),
            _ent("com.apple.security.cs.disable-library-validation", "injection", critical=True),
            _ent("com.apple.security.keychain-access-groups", "keychain"),
            _ent("com.apple.security.network.client", "network"),
        ],
        injection_methods=["dyld_insert_via_entitlement", "missing_library_validation", "electron_env_var"],
    ),

    # 15. Acme Shell Helper — DYLD environment entitlement → shell hook injection
    ApplicationData(
        name="Acme Shell Helper",
        bundle_id="com.acmecorp.shellhelper",
        path="/Applications/Acme Shell Helper.app",
        version="1.2.0",
        team_id="ACME123456",
        hardened_runtime=False,
        library_validation=False,
        is_electron=False,
        is_system=False,
        signed=True,
        is_notarized=True,
        signing_certificate_cn="Developer ID Application: Acme Corp (ACME123456)",
        signing_certificate_sha256="04050601020300000000000000000000000000000000000000000000000000ab",
        certificate_expires="2028-06-15T00:00:00Z",
        certificate_chain_length=3,
        certificate_chain=_apple_cert_chain(
            "Developer ID Application: Acme Corp (ACME123456)",
            "Acme Corp",
            "0405060102030000ab",
        ),
        entitlements=[
            _ent("com.apple.security.cs.allow-dyld-environment-variables", "injection", critical=True),
            _ent("com.apple.security.cs.disable-library-validation", "injection", critical=True),
        ],
        injection_methods=["dyld_insert_via_entitlement", "missing_library_validation"],
    ),
]

# ---------------------------------------------------------------------------
# TCC grants (~15 across Camera, Mic, Accessibility, FDA, Screen Recording, Apple Events)
# ---------------------------------------------------------------------------

tcc_grants: list[TCCGrantData] = [
    # iTerm2 — FDA (the critical one)
    TCCGrantData(
        service="kTCCServiceSystemPolicyAllFiles", display_name="Full Disk Access",
        client="com.googlecode.iterm2", client_type=0, auth_value=2, auth_reason=2,
        scope="user", last_modified=1710748800,
    ),
    # iTerm2 — Accessibility
    TCCGrantData(
        service="kTCCServiceAccessibility", display_name="Accessibility",
        client="com.googlecode.iterm2", client_type=0, auth_value=2, auth_reason=2,
        scope="user", last_modified=1710748800,
    ),
    # Slack — Camera
    TCCGrantData(
        service="kTCCServiceCamera", display_name="Camera",
        client="com.tinyspeck.slackmacgap", client_type=0, auth_value=2, auth_reason=1,
        scope="user", last_modified=1710748800,
    ),
    # Slack — Microphone
    TCCGrantData(
        service="kTCCServiceMicrophone", display_name="Microphone",
        client="com.tinyspeck.slackmacgap", client_type=0, auth_value=2, auth_reason=1,
        scope="user", last_modified=1710748800,
    ),
    # Slack — Screen Recording
    TCCGrantData(
        service="kTCCServiceScreenCapture", display_name="Screen Recording",
        client="com.tinyspeck.slackmacgap", client_type=0, auth_value=2, auth_reason=1,
        scope="user", last_modified=1710748800,
    ),
    # VS Code — Accessibility
    TCCGrantData(
        service="kTCCServiceAccessibility", display_name="Accessibility",
        client="com.microsoft.VSCode", client_type=0, auth_value=2, auth_reason=1,
        scope="user", last_modified=1710748800,
    ),
    # Zoom — Camera
    TCCGrantData(
        service="kTCCServiceCamera", display_name="Camera",
        client="us.zoom.xos", client_type=0, auth_value=2, auth_reason=1,
        scope="user", last_modified=1710748800,
    ),
    # Zoom — Microphone
    TCCGrantData(
        service="kTCCServiceMicrophone", display_name="Microphone",
        client="us.zoom.xos", client_type=0, auth_value=2, auth_reason=1,
        scope="user", last_modified=1710748800,
    ),
    # OmniGraffle — Apple Events (automation → Finder)
    TCCGrantData(
        service="kTCCServiceAppleEvents", display_name="Automation",
        client="com.omnigroup.OmniGraffle7", client_type=0, auth_value=2, auth_reason=1,
        scope="user", last_modified=1710748800,
    ),
    # Acme Backup — FDA (via MDM)
    TCCGrantData(
        service="kTCCServiceSystemPolicyAllFiles", display_name="Full Disk Access",
        client="com.acmecorp.backup", client_type=0, auth_value=2, auth_reason=4,
        scope="system", last_modified=1710748800,
    ),
    # Acme Analytics — Camera
    TCCGrantData(
        service="kTCCServiceCamera", display_name="Camera",
        client="com.acmecorp.analytics", client_type=0, auth_value=2, auth_reason=1,
        scope="user", last_modified=1710748800,
    ),
    # System Settings — FDA (system)
    TCCGrantData(
        service="kTCCServiceSystemPolicyAllFiles", display_name="Full Disk Access",
        client="com.apple.systempreferences", client_type=0, auth_value=2, auth_reason=5,
        scope="system", last_modified=1710748800,
    ),
    # Finder — FDA (system, implicit)
    TCCGrantData(
        service="kTCCServiceSystemPolicyAllFiles", display_name="Full Disk Access",
        client="com.apple.finder", client_type=0, auth_value=2, auth_reason=5,
        scope="system", last_modified=1710748800,
    ),
    # Finder — Apple Events target (for OmniGraffle → Finder chain)
    TCCGrantData(
        service="kTCCServiceAppleEvents", display_name="Automation",
        client="com.apple.finder", client_type=0, auth_value=2, auth_reason=5,
        scope="system", last_modified=1710748800,
    ),
    # 1Password — Keychain sharing (not a TCC per se, but relevant for keychain queries)
    TCCGrantData(
        service="kTCCServiceAccessibility", display_name="Accessibility",
        client="com.1password.1password", client_type=0, auth_value=2, auth_reason=1,
        scope="user", last_modified=1710748800,
    ),
]

# ---------------------------------------------------------------------------
# XPC services (5)
# ---------------------------------------------------------------------------

xpc_services: list[XPCServiceData] = [
    # Acme VPN — NO client verification → Query 30
    XPCServiceData(
        label="com.acmecorp.vpn.tunnel",
        path="/Library/LaunchDaemons/com.acmecorp.vpn.tunnel.plist",
        program="/Library/Application Support/Acme VPN/acme-vpn-tunnel",
        type="daemon",
        user="root",
        run_at_load=True,
        keep_alive=True,
        mach_services=["com.acmecorp.vpn.tunnel.xpc"],
        entitlements=["com.apple.developer.networking.networkextension"],
        has_client_verification=False,
    ),
    # Acme Backup helper — with client verification (safe)
    XPCServiceData(
        label="com.acmecorp.backup.helper",
        path="/Library/LaunchDaemons/com.acmecorp.backup.helper.plist",
        program="/Library/PrivilegedHelperTools/com.acmecorp.backup.helper",
        type="daemon",
        user="root",
        run_at_load=True,
        keep_alive=True,
        mach_services=["com.acmecorp.backup.helper.xpc"],
        entitlements=["com.apple.private.tcc.allow"],
        has_client_verification=True,
    ),
    # System XPC — com.apple.security.authtrampoline
    XPCServiceData(
        label="com.apple.security.authtrampoline",
        path="/System/Library/LaunchDaemons/com.apple.security.authtrampoline.plist",
        program="/usr/libexec/security_authtrampoline",
        type="daemon",
        user="root",
        run_at_load=False,
        keep_alive=False,
        mach_services=["com.apple.security.authtrampoline"],
        entitlements=[],
        has_client_verification=True,
    ),
    # Acme Shell Helper XPC — no client verification
    XPCServiceData(
        label="com.acmecorp.shellhelper.xpc",
        path="/Library/LaunchAgents/com.acmecorp.shellhelper.xpc.plist",
        program="/Applications/Acme Shell Helper.app/Contents/XPCServices/shellhelper",
        type="agent",
        run_at_load=True,
        keep_alive=False,
        mach_services=["com.acmecorp.shellhelper.xpc"],
        entitlements=[],
        has_client_verification=False,
    ),
    # Acme Launcher helper agent
    XPCServiceData(
        label="com.acmecorp.launcher.agent",
        path="/Library/LaunchAgents/com.acmecorp.launcher.agent.plist",
        program="/Applications/Acme Launcher.app/Contents/MacOS/launcher-agent",
        type="agent",
        run_at_load=True,
        keep_alive=False,
        mach_services=["com.acmecorp.launcher.agent.xpc"],
        entitlements=[],
        has_client_verification=True,
    ),
]

# ---------------------------------------------------------------------------
# Launch items (6) — one with writable plist for Query 29
# ---------------------------------------------------------------------------

launch_items: list[LaunchItemData] = [
    LaunchItemData(
        label="com.acmecorp.vpn.tunnel",
        path="/Library/LaunchDaemons/com.acmecorp.vpn.tunnel.plist",
        type="daemon",
        program="/Library/Application Support/Acme VPN/acme-vpn-tunnel",
        run_at_load=True,
        user="root",
        plist_owner="root",
        program_owner="root",
    ),
    LaunchItemData(
        label="com.acmecorp.backup.helper",
        path="/Library/LaunchDaemons/com.acmecorp.backup.helper.plist",
        type="daemon",
        program="/Library/PrivilegedHelperTools/com.acmecorp.backup.helper",
        run_at_load=True,
        user="root",
        plist_owner="root",
        program_owner="root",
    ),
    # Writable plist → Query 29 (hijackable launch daemon)
    LaunchItemData(
        label="com.acmecorp.launcher.agent",
        path="/Library/LaunchAgents/com.acmecorp.launcher.agent.plist",
        type="agent",
        program="/Applications/Acme Launcher.app/Contents/MacOS/launcher-agent",
        run_at_load=True,
        plist_owner="demouser",
        program_owner="root",
        plist_writable_by_non_root=True,
    ),
    LaunchItemData(
        label="com.acmecorp.shellhelper",
        path="/Library/LaunchAgents/com.acmecorp.shellhelper.plist",
        type="agent",
        program="/Applications/Acme Shell Helper.app/Contents/MacOS/shellhelper",
        run_at_load=True,
        plist_owner="root",
        program_owner="root",
    ),
    LaunchItemData(
        label="com.apple.security.authtrampoline",
        path="/System/Library/LaunchDaemons/com.apple.security.authtrampoline.plist",
        type="daemon",
        program="/usr/libexec/security_authtrampoline",
        run_at_load=False,
        user="root",
        plist_owner="root",
        program_owner="root",
    ),
    LaunchItemData(
        label="com.acmecorp.analytics.reporter",
        path="/Library/LaunchAgents/com.acmecorp.analytics.reporter.plist",
        type="agent",
        program="/Applications/Acme Analytics.app/Contents/MacOS/reporter",
        run_at_load=True,
        plist_owner="root",
        program_owner="root",
    ),
]

# ---------------------------------------------------------------------------
# Keychain ACLs (4) — 1Password and Slack with trusted app lists
# ---------------------------------------------------------------------------

keychain_acls: list[KeychainItemData] = [
    KeychainItemData(
        label="1Password Vault Key",
        kind="generic_password",
        service="com.1password.1password.vault",
        access_group="2BUA8C4S2C.com.1password.1password",
        trusted_apps=["com.1password.1password"],
        sensitivity="critical",
    ),
    KeychainItemData(
        label="Slack API Token",
        kind="internet_password",
        service="slack.com",
        access_group=None,
        trusted_apps=["com.tinyspeck.slackmacgap", "com.apple.Safari"],
        sensitivity="high",
    ),
    KeychainItemData(
        label="Acme VPN Certificate",
        kind="certificate",
        service="com.acmecorp.vpn",
        access_group="ACME123456.com.acmecorp.vpn",
        trusted_apps=["com.acmecorp.vpn"],
        sensitivity="high",
    ),
    KeychainItemData(
        label="Developer ID Certificate",
        kind="certificate",
        service=None,
        access_group="com.apple.security",
        trusted_apps=[],
        sensitivity="medium",
    ),
]

# ---------------------------------------------------------------------------
# MDM profile — grants FDA to Acme Backup via policy
# ---------------------------------------------------------------------------

mdm_profiles: list[MDMProfileData] = [
    MDMProfileData(
        identifier="com.acmecorp.mdm.privacy-prefs",
        display_name="Acme Corp Privacy Preferences",
        organization="Acme Corp IT",
        install_date="2026-01-15 09:00:00 +0000",
        tcc_policies=[
            TCCPolicyData(service="SystemPolicyAllFiles", client_bundle_id="com.acmecorp.backup", allowed=True),
            TCCPolicyData(service="SystemPolicyAllFiles", client_bundle_id="com.acmecorp.analytics", allowed=True),
        ],
    ),
]

# ---------------------------------------------------------------------------
# Local groups
# ---------------------------------------------------------------------------

local_groups: list[LocalGroupData] = [
    LocalGroupData(name="admin", gid=80, members=["demouser"]),
    LocalGroupData(name="_developer", gid=204, members=["demouser"]),
    LocalGroupData(name="com.apple.access_ssh", gid=399, members=["demouser"]),
    LocalGroupData(name="wheel", gid=0, members=["demouser"]),
]

# ---------------------------------------------------------------------------
# Remote access, firewall, login sessions
# ---------------------------------------------------------------------------

remote_access_services: list[RemoteAccessServiceData] = [
    RemoteAccessServiceData(service="ssh", enabled=True, port=22, config={"PermitRootLogin": "no"}),
]

firewall_status: list[FirewallStatusData] = [
    FirewallStatusData(
        enabled=True,
        stealth_mode=False,
        allow_signed=True,
        allow_built_in=True,
        app_rules=[
            FirewallAppRuleData(bundle_id="com.acmecorp.vpn", allow_incoming=True),
            FirewallAppRuleData(bundle_id="com.tinyspeck.slackmacgap", allow_incoming=False),
        ],
    ),
]

login_sessions: list[LoginSessionData] = [
    LoginSessionData(username="demouser", terminal="console", login_time="Mar 20 09:15", session_type="console"),
    LoginSessionData(username="demouser", terminal="ttys000", login_time="Mar 20 09:30", session_type="ssh"),
]

# ---------------------------------------------------------------------------
# Authorization rights & plugins
# ---------------------------------------------------------------------------

authorization_rights: list[AuthorizationRightData] = [
    AuthorizationRightData(name="system.privilege.admin", rule="authenticate-admin-nonshared",
                           allow_root=True, require_authentication=True),
    AuthorizationRightData(name="system.preferences", rule="authenticate-session-owner",
                           allow_root=False, require_authentication=True),
    AuthorizationRightData(name="com.acmecorp.vpn.install-helper", rule="allow",
                           allow_root=True, require_authentication=False),
]

authorization_plugins: list[AuthorizationPluginData] = [
    AuthorizationPluginData(
        name="AcmeAuthPlugin",
        path="/Library/Security/SecurityAgentPlugins/AcmeAuthPlugin.bundle",
        team_id="ACME123456",
    ),
]

# ---------------------------------------------------------------------------
# System extensions, sudoers, running processes
# ---------------------------------------------------------------------------

system_extensions: list[SystemExtensionData] = [
    SystemExtensionData(
        identifier="com.acmecorp.vpn.tunnel",
        team_id="ACME123456",
        extension_type="network",
        enabled=True,
    ),
]

sudoers_rules: list[SudoersRuleData] = [
    SudoersRuleData(user="demouser", host="ALL", command="ALL", nopasswd=True),
]

running_processes: list[RunningProcessData] = [
    RunningProcessData(pid=501, user="demouser", command="/Applications/iTerm.app/Contents/MacOS/iTerm2",
                       bundle_id="com.googlecode.iterm2"),
    RunningProcessData(pid=612, user="demouser", command="/Applications/Slack.app/Contents/MacOS/Slack",
                       bundle_id="com.tinyspeck.slackmacgap"),
    RunningProcessData(pid=723, user="demouser",
                       command="/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
                       bundle_id="com.microsoft.VSCode"),
    RunningProcessData(pid=834, user="demouser", command="/Applications/1Password.app/Contents/MacOS/1Password",
                       bundle_id="com.1password.1password"),
    RunningProcessData(pid=945, user="demouser",
                       command="/Applications/Acme Shell Helper.app/Contents/MacOS/shellhelper",
                       bundle_id="com.acmecorp.shellhelper"),
    RunningProcessData(pid=1056, user="root",
                       command="/Library/Application Support/Acme VPN/acme-vpn-tunnel",
                       bundle_id="com.acmecorp.vpn"),
]

# ---------------------------------------------------------------------------
# User details
# ---------------------------------------------------------------------------

user_details: list[UserDetailData] = [
    UserDetailData(name="demouser", shell="/bin/zsh", home_dir="/Users/demouser"),
    UserDetailData(name="_acmebackup", shell="/usr/bin/false", home_dir="/var/empty", is_hidden=True),
]

# ---------------------------------------------------------------------------
# File ACLs — writable LaunchAgent dir, TCC.db, sudoers
# ---------------------------------------------------------------------------

file_acls: list[FileACLData] = [
    FileACLData(
        path="/Library/Application Support/com.apple.TCC/TCC.db",
        owner="root", group="admin", mode="644",
        is_sip_protected=False, is_writable_by_non_root=False,
        category="tcc_database",
    ),
    FileACLData(
        path="/Users/demouser/Library/Application Support/com.apple.TCC/TCC.db",
        owner="demouser", group="staff", mode="644",
        is_sip_protected=False, is_writable_by_non_root=False,
        category="tcc_database",
    ),
    FileACLData(
        path="/etc/sudoers",
        owner="root", group="wheel", mode="440",
        is_sip_protected=False, is_writable_by_non_root=False,
        category="sudoers",
    ),
    FileACLData(
        path="/Library/LaunchAgents",
        owner="root", group="wheel", mode="775",
        is_sip_protected=False, is_writable_by_non_root=True,
        category="launch_agent_dir",
    ),
    FileACLData(
        path="/Users/demouser/.zshrc",
        owner="demouser", group="staff", mode="644",
        is_sip_protected=False, is_writable_by_non_root=True,
        category="shell_hook",
    ),
]

# ---------------------------------------------------------------------------
# Bluetooth, AD binding, Kerberos, physical security
# ---------------------------------------------------------------------------

bluetooth_devices: list[BluetoothDeviceData] = [
    BluetoothDeviceData(name="Magic Keyboard", address="AA:BB:CC:DD:EE:01", device_type="Keyboard", connected=True),
    BluetoothDeviceData(name="AirPods Pro", address="AA:BB:CC:DD:EE:02", device_type="Headphones", connected=False),
    BluetoothDeviceData(name="Magic Mouse", address="AA:BB:CC:DD:EE:03", device_type="Mouse", connected=True),
]

ad_binding = ADBindingData(is_bound=False)

kerberos_artifacts: list[KerberosArtifactData] = [
    KerberosArtifactData(
        path="/etc/krb5.conf",
        artifact_type="config",
        owner="root", group="wheel", mode="644",
        modification_time="2026-01-15T12:00:00Z",
        is_readable=True, is_world_readable=True, is_group_readable=True,
        default_realm="ACMECORP.LOCAL",
        permitted_enc_types=["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"],
        realm_names=["ACMECORP.LOCAL"],
        is_forwardable=True,
    ),
]

# ---------------------------------------------------------------------------
# Assemble the full scan
# ---------------------------------------------------------------------------

scan_data = {
    "scan_id": "demo-0001-acme-macbook-pro",
    "timestamp": "2026-03-20T10:00:00Z",
    "hostname": "acme-macbook-pro",
    "macos_version": "macOS 15.3 (Build 24D60)",
    "collector_version": "0.1.0",
    "elevation": ElevationInfo(is_root=True, has_fda=True),
    "applications": applications,
    "tcc_grants": tcc_grants,
    "xpc_services": xpc_services,
    "keychain_acls": keychain_acls,
    "mdm_profiles": mdm_profiles,
    "launch_items": launch_items,
    "local_groups": local_groups,
    "remote_access_services": remote_access_services,
    "firewall_status": firewall_status,
    "login_sessions": login_sessions,
    "authorization_rights": authorization_rights,
    "authorization_plugins": authorization_plugins,
    "system_extensions": system_extensions,
    "sudoers_rules": sudoers_rules,
    "running_processes": running_processes,
    "user_details": user_details,
    "file_acls": file_acls,
    "bluetooth_devices": bluetooth_devices,
    "ad_binding": ad_binding,
    "kerberos_artifacts": kerberos_artifacts,
    # Physical security posture
    "gatekeeper_enabled": True,
    "sip_enabled": True,
    "filevault_enabled": False,
    "lockdown_mode_enabled": False,
    "bluetooth_enabled": True,
    "bluetooth_discoverable": True,
    "screen_lock_enabled": True,
    "screen_lock_delay": 300,
    "display_sleep_timeout": 15,
    "thunderbolt_security_level": "user_authorization",
    "secure_boot_level": "full",
    "external_boot_allowed": False,
    # iCloud
    "icloud_signed_in": True,
    "icloud_drive_enabled": True,
    "icloud_keychain_enabled": True,
    # Errors
    "errors": [
        CollectionErrorData(source="Keychain", message="Some keychain items require unlock", recoverable=True),
    ],
}

# ---------------------------------------------------------------------------
# Validate & write
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Generate a synthetic Rootstock demo scan")
    parser.add_argument("-o", "--output", default=str(Path(__file__).parent / "demo-scan.json"),
                        help="Output file path (default: examples/demo-scan.json)")
    args = parser.parse_args()

    # Schema validation — will raise if models.py changed in an incompatible way
    scan = ScanResult.model_validate(scan_data)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(scan.model_dump(), indent=2) + "\n")
    print(f"Wrote {output_path} ({output_path.stat().st_size:,} bytes, "
          f"{len(scan.applications)} apps, {len(scan.tcc_grants)} TCC grants)")


if __name__ == "__main__":
    main()
