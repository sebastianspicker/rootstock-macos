"""
constants.py — Shared constants for the Rootstock graph pipeline.
"""

from __future__ import annotations

ATTACKER_BUNDLE_ID = "attacker.payload"
ATTACKER_NAME = "Attacker Payload"

ALLOW_DYLD_ENTITLEMENT = "com.apple.security.cs.allow-dyld-environment-variables"
REQUIRE_LIB_VALIDATION_ENTITLEMENT = "com.apple.security.cs.require-library-validation"
DISABLE_LIB_VALIDATION_ENTITLEMENT = "com.apple.security.cs.disable-library-validation"
PRIVATE_TCC_ALLOW_ENTITLEMENT = "com.apple.private.tcc.allow"

# TCC service identifiers — canonical names matching Apple's internal strings
FDA_SERVICE = "kTCCServiceSystemPolicyAllFiles"
APPLE_EVENTS_SERVICE = "kTCCServiceAppleEvents"
ACCESSIBILITY_SERVICE = "kTCCServiceAccessibility"
SCREEN_CAPTURE_SERVICE = "kTCCServiceScreenCapture"
CAMERA_SERVICE = "kTCCServiceCamera"
MICROPHONE_SERVICE = "kTCCServiceMicrophone"
CONTACTS_SERVICE = "kTCCServiceAddressBook"
CALENDAR_SERVICE = "kTCCServiceCalendar"
PHOTOS_SERVICE = "kTCCServicePhotos"

# Injection method labels (match InjectionMethod Literal in models.py)
INJECTION_DYLD_INSERT = "dyld_insert"
INJECTION_DYLD_ENTITLEMENT = "dyld_insert_via_entitlement"
INJECTION_MISSING_LIB_VAL = "missing_library_validation"
INJECTION_ELECTRON_ENV = "electron_env_var"

# Owned-node workflow properties
OWNED_PROPERTY = "owned"
OWNED_AT_PROPERTY = "owned_at"
TIER_PROPERTY = "tier"

# Risk scoring properties (set by infer_risk_score.py)
RISK_SCORE_PROPERTY = "risk_score"
RISK_LEVEL_PROPERTY = "risk_level"
ATTACK_CATEGORIES_PROPERTY = "attack_categories"
CRITICAL_FINDING_COUNT_PROPERTY = "critical_finding_count"
HIGH_FINDING_COUNT_PROPERTY = "high_finding_count"

# Canonical mapping of Neo4j labels to their unique key property.
# Used by mark_owned.py (for node lookup) and opengraph_export.py (for ID generation).
# Keychain_Item uses a composite key (label+kind) handled separately where needed.
NODE_KEY_PROPERTY: dict[str, str] = {
    "Application": "bundle_id",
    "TCC_Permission": "service",
    "Entitlement": "name",
    "XPC_Service": "label",
    "LaunchItem": "label",
    "MDM_Profile": "identifier",
    "User": "name",
    "LocalGroup": "name",
    "RemoteAccessService": "service",
    "FirewallPolicy": "name",
    "LoginSession": "terminal",
    "AuthorizationRight": "name",
    "AuthorizationPlugin": "name",
    "SystemExtension": "identifier",
    "SudoersRule": "key",
    "CriticalFile": "path",
    "Computer": "hostname",
    "CertificateAuthority": "sha256",
    "BluetoothDevice": "address",
    "KerberosArtifact": "path",
    "ADGroup": "name",
    "Vulnerability": "cve_id",
    "AttackTechnique": "technique_id",
    "SandboxProfile": "bundle_id",
    "ADUser": "object_id",
    "ThreatGroup": "group_id",
    "CWE": "cwe_id",
    "Recommendation": "key",
}
