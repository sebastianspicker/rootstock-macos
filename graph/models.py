"""
models.py — Pydantic v2 models mirroring the Rootstock collector JSON schema.

These models validate scan output early and provide typed access throughout
the importer pipeline. They intentionally mirror `collector/schema/scan-result.schema.json`.
"""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ElevationInfo(BaseModel):
    is_root: bool
    has_fda: bool


class EntitlementData(BaseModel):
    name: str = Field(min_length=1)
    is_private: bool
    category: Literal[
        "tcc",
        "injection",
        "privilege",
        "sandbox",
        "keychain",
        "network",
        "icloud",
        "other",
    ]
    is_security_critical: bool


InjectionMethod = Literal[
    "dyld_insert",
    "dyld_insert_via_entitlement",
    "missing_library_validation",
    "electron_env_var",
]


class CertificateDetailData(BaseModel):
    common_name: str | None = None
    organization: str | None = None
    sha256: str = Field(min_length=1)
    valid_from: str | None = None
    valid_to: str | None = None
    is_root: bool = False


class SandboxProfileData(BaseModel):
    bundle_id: str = Field(min_length=1)
    profile_source: str = Field(min_length=1)
    file_read_rules: list[str] = Field(default_factory=list)
    file_write_rules: list[str] = Field(default_factory=list)
    mach_lookup_rules: list[str] = Field(default_factory=list)
    network_rules: list[str] = Field(default_factory=list)
    iokit_rules: list[str] = Field(default_factory=list)
    exception_count: int = 0
    has_unconstrained_network: bool = False
    has_unconstrained_file_read: bool = False


class QuarantineInfoData(BaseModel):
    has_quarantine_flag: bool
    quarantine_agent: str | None = None
    quarantine_timestamp: str | None = None
    was_user_approved: bool = False
    was_translocated: bool = False


class ApplicationData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    bundle_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    version: str | None = None
    team_id: str | None = None
    hardened_runtime: bool
    library_validation: bool
    is_electron: bool
    is_system: bool
    signed: bool
    is_sip_protected: bool = False
    is_sandboxed: bool = False
    sandbox_exceptions: list[str] = Field(default_factory=list)
    is_notarized: bool | None = None
    is_adhoc_signed: bool = False
    signing_certificate_cn: str | None = None
    signing_certificate_sha256: str | None = None
    certificate_expires: str | None = None
    is_certificate_expired: bool = False
    certificate_chain_length: int | None = None
    certificate_trust_valid: bool | None = None
    certificate_chain: list[CertificateDetailData] = Field(default_factory=list)
    entitlements: list[EntitlementData] = Field(default_factory=list)
    injection_methods: list[InjectionMethod] = Field(default_factory=list)
    launch_constraint_category: str | None = None
    sandbox_profile: SandboxProfileData | None = None
    quarantine_info: QuarantineInfoData | None = None


class TCCGrantData(BaseModel):
    service: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    client: str = Field(min_length=1)
    client_type: int
    auth_value: int
    auth_reason: int
    scope: Literal["user", "system"]
    last_modified: (
        int  # Intentionally stored as integer (Unix timestamp format from TCC.db)
    )

    @property
    def allowed(self) -> bool:
        """auth_value 2 = allowed, 3 = limited (also allowed)."""
        return self.auth_value in (2, 3)

    @property
    def auth_reason_label(self) -> str:
        labels = {
            1: "user_prompt",
            2: "system_settings",
            3: "entitlement",
            4: "mdm",
            5: "system",
        }
        return labels.get(self.auth_reason, f"unknown_{self.auth_reason}")


class TCCPolicyData(BaseModel):
    service: str = Field(min_length=1)
    client_bundle_id: str = Field(min_length=1)
    allowed: bool


class MDMProfileData(BaseModel):
    identifier: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    organization: str | None = None
    install_date: str | None = None
    tcc_policies: list[TCCPolicyData] = Field(default_factory=list)


KeychainSensitivity = Literal["critical", "high", "medium", "low"]


class KeychainItemData(BaseModel):
    label: str = Field(min_length=1)
    kind: Literal["generic_password", "internet_password", "certificate", "key"]
    service: str | None = None
    access_group: str | None = None
    trusted_apps: list[str] = Field(default_factory=list)
    sensitivity: KeychainSensitivity | None = None


class LaunchItemData(BaseModel):
    label: str = Field(min_length=1)
    path: str = Field(min_length=1)
    type: Literal["daemon", "agent", "login_item", "cron", "login_hook"]
    program: str | None = None
    run_at_load: bool = False
    user: str | None = None
    plist_owner: str | None = None
    program_owner: str | None = None
    plist_writable_by_non_root: bool = False
    program_writable_by_non_root: bool = False


class XPCServiceData(BaseModel):
    label: str = Field(min_length=1)
    path: str = Field(min_length=1)
    program: str | None = None
    type: Literal["daemon", "agent"]
    user: str | None = None
    run_at_load: bool = False
    keep_alive: bool = False
    mach_services: list[str] = Field(default_factory=list)
    entitlements: list[str] = Field(default_factory=list)
    has_client_verification: bool = False


class LocalGroupData(BaseModel):
    name: str = Field(min_length=1)
    gid: int
    members: list[str] = Field(default_factory=list)


class RemoteAccessServiceData(BaseModel):
    service: Literal["ssh", "screen_sharing"]
    enabled: bool | None = None
    port: int | None = None
    config: dict[str, str] = Field(default_factory=dict)


class FirewallAppRuleData(BaseModel):
    bundle_id: str = Field(min_length=1)
    allow_incoming: bool


class FirewallStatusData(BaseModel):
    enabled: bool | None = None
    stealth_mode: bool | None = None
    allow_signed: bool | None = None
    allow_built_in: bool | None = None
    app_rules: list[FirewallAppRuleData] = Field(default_factory=list)


class LoginSessionData(BaseModel):
    username: str = Field(min_length=1)
    terminal: str = Field(min_length=1)
    login_time: str = Field(min_length=1)
    session_type: Literal["console", "ssh", "screen_sharing", "tmux"]


class AuthorizationRightData(BaseModel):
    name: str = Field(min_length=1)
    rule: str | None = None
    allow_root: bool = False
    require_authentication: bool = True


class AuthorizationPluginData(BaseModel):
    name: str = Field(min_length=1)
    path: str = Field(min_length=1)
    team_id: str | None = None


class SystemExtensionData(BaseModel):
    identifier: str = Field(min_length=1)
    team_id: str | None = None
    extension_type: Literal["network", "endpoint_security", "driver"]
    enabled: bool
    subscribed_events: list[str] = Field(default_factory=list)


class SudoersRuleData(BaseModel):
    user: str = Field(min_length=1)
    host: str = "ALL"
    command: str = Field(min_length=1)
    nopasswd: bool


class RunningProcessData(BaseModel):
    pid: int
    user: str = Field(min_length=1)
    command: str = Field(min_length=1)
    bundle_id: str | None = None


class UserDetailData(BaseModel):
    name: str = Field(min_length=1)
    shell: str | None = None
    home_dir: str | None = None
    is_hidden: bool = False
    is_ad_user: bool = False


FileACLCategory = Literal[
    "tcc_database",
    "keychain",
    "sudoers",
    "ssh_config",
    "launch_agent_dir",
    "launch_daemon_dir",
    "authorization_db",
    "shell_hook",
]


class FileACLData(BaseModel):
    path: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    group: str = Field(min_length=1)
    mode: str = Field(min_length=1)
    acl_entries: list[str] = Field(default_factory=list)
    is_sip_protected: bool = False
    is_writable_by_non_root: bool = False
    category: FileACLCategory


class BluetoothDeviceData(BaseModel):
    name: str = Field(min_length=1)
    address: str = Field(min_length=1)
    device_type: str = Field(min_length=1)
    connected: bool


class ADGroupMappingData(BaseModel):
    ad_group: str = Field(min_length=1)
    local_group: str = Field(min_length=1)


class ADBindingData(BaseModel):
    is_bound: bool
    realm: str | None = None
    forest: str | None = None
    computer_account: str | None = None
    organizational_unit: str | None = None
    preferred_dc: str | None = None
    group_mappings: list[ADGroupMappingData] = Field(default_factory=list)


KerberosArtifactType = Literal["ccache", "keytab", "config"]


class KerberosArtifactData(BaseModel):
    path: str = Field(min_length=1)
    artifact_type: KerberosArtifactType
    owner: str | None = None
    group: str | None = None
    mode: str | None = None
    modification_time: str | None = None
    principal_hint: str | None = None
    is_readable: bool = False
    is_world_readable: bool = False
    is_group_readable: bool = False
    # krb5.conf parsed fields (config type only)
    default_realm: str | None = None
    permitted_enc_types: list[str] | None = None
    realm_names: list[str] | None = None
    is_forwardable: bool | None = None


class CollectionErrorData(BaseModel):
    source: str = Field(min_length=1)
    message: str = Field(min_length=1)
    recoverable: bool


class ComputerData(BaseModel):
    """Represents a scanned macOS host. Auto-derived from ScanResult metadata."""

    hostname: str = Field(min_length=1)
    macos_version: str = Field(min_length=1)
    scan_id: str = Field(min_length=1)
    scanned_at: str = Field(min_length=1)
    collector_version: str = Field(min_length=1)
    elevation_is_root: bool = False
    elevation_has_fda: bool = False


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    hostname: str = Field(min_length=1)
    macos_version: str = Field(min_length=1)
    collector_version: str = Field(min_length=1)
    elevation: ElevationInfo
    applications: list[ApplicationData] = Field(default_factory=list)
    tcc_grants: list[TCCGrantData] = Field(default_factory=list)
    xpc_services: list[XPCServiceData] = Field(default_factory=list)
    keychain_acls: list[KeychainItemData] = Field(default_factory=list)
    mdm_profiles: list[MDMProfileData] = Field(default_factory=list)
    launch_items: list[LaunchItemData] = Field(default_factory=list)
    local_groups: list[LocalGroupData] = Field(default_factory=list)
    remote_access_services: list[RemoteAccessServiceData] = Field(default_factory=list)
    firewall_status: list[FirewallStatusData] = Field(default_factory=list)
    login_sessions: list[LoginSessionData] = Field(default_factory=list)
    authorization_rights: list[AuthorizationRightData] = Field(default_factory=list)
    authorization_plugins: list[AuthorizationPluginData] = Field(default_factory=list)
    system_extensions: list[SystemExtensionData] = Field(default_factory=list)
    sudoers_rules: list[SudoersRuleData] = Field(default_factory=list)
    running_processes: list[RunningProcessData] = Field(default_factory=list)
    user_details: list[UserDetailData] = Field(default_factory=list)
    file_acls: list[FileACLData] = Field(default_factory=list)
    bluetooth_devices: list[BluetoothDeviceData] = Field(default_factory=list)
    ad_binding: ADBindingData | None = None
    kerberos_artifacts: list[KerberosArtifactData] = Field(default_factory=list)
    sandbox_profiles: list[SandboxProfileData] = Field(default_factory=list)
    gatekeeper_enabled: bool | None = None
    sip_enabled: bool | None = None
    filevault_enabled: bool | None = None
    lockdown_mode_enabled: bool | None = None
    bluetooth_enabled: bool | None = None
    bluetooth_discoverable: bool | None = None
    screen_lock_enabled: bool | None = None
    screen_lock_delay: int | None = None
    display_sleep_timeout: int | None = None
    thunderbolt_security_level: str | None = None
    secure_boot_level: str | None = None
    external_boot_allowed: bool | None = None
    icloud_signed_in: bool | None = None
    icloud_drive_enabled: bool | None = None
    icloud_keychain_enabled: bool | None = None
    errors: list[CollectionErrorData] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_unique_bundle_ids(self) -> ScanResult:
        import logging

        _logger = logging.getLogger(__name__)
        seen: set[str] = set()
        deduped: list[ApplicationData] = []
        for app in self.applications:
            if app.bundle_id in seen:
                _logger.warning(
                    "Duplicate bundle_id '%s' — keeping first occurrence, discarding duplicate at path '%s'",
                    app.bundle_id,
                    app.path,
                )
                continue
            seen.add(app.bundle_id)
            deduped.append(app)
        self.applications = deduped
        return self
