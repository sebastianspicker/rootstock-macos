"""
models_inventory.py - Pydantic models for the collector's inventory evidence.

Network listeners, certificate trust settings, browser extensions, installer
receipts, host security settings and network configuration, mirroring the
corresponding ``$defs`` in ``contracts/collector-scan/legacy-unversioned.schema.json``.
``models.ScanResult`` composes them; importers use them directly.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class NetworkListenerData(BaseModel):
    protocol: Literal["tcp", "udp"]
    address: str = Field(min_length=1)
    port: int
    is_loopback: bool
    state: Literal["listen", "bound"]
    pid: int | None = None
    process_name: str | None = None
    user: str | None = None
    bundle_id: str | None = None


class TrustedCertificateData(BaseModel):
    sha256: str = Field(min_length=1)
    subject: str
    issuer: str | None = None
    domain: Literal["user", "admin"]
    trust_result: Literal["trust_root", "trust_as_root", "deny", "unspecified", "invalid"]
    is_self_signed: bool
    not_after: str | None = None


BrowserName = Literal[
    "chrome", "chromium", "brave", "edge", "vivaldi", "arc", "opera", "firefox", "safari"
]
ExtensionInstallLocation = Literal[
    "webstore", "unpacked", "external", "policy", "component", "unknown"
]


class BrowserExtensionData(BaseModel):
    browser: BrowserName
    browser_bundle_id: str | None = None
    profile: str
    extension_id: str = Field(min_length=1)
    name: str
    version: str
    manifest_version: int | None = None
    permissions: list[str] = Field(default_factory=list)
    host_permissions: list[str] = Field(default_factory=list)
    from_webstore: bool | None = None
    enabled: bool | None = None
    install_time: str | None = None
    install_location: ExtensionInstallLocation
    path: str = Field(min_length=1)


class InstalledPackageData(BaseModel):
    package_id: str = Field(min_length=1)
    version: str | None = None
    install_date: str | None = None
    install_prefix: str | None = None
    install_process: str | None = None
    package_file_name: str | None = None
    is_apple: bool


class SoftwareUpdateSettingsData(BaseModel):
    automatic_check: bool | None = None
    automatic_download: bool | None = None
    install_security_responses: bool | None = None
    install_system_updates: bool | None = None
    install_app_updates: bool | None = None
    last_successful_check: str | None = None


class HostSecuritySettingsData(BaseModel):
    guest_account_enabled: bool | None = None
    auto_login_user: str | None = None
    root_account_enabled: bool | None = None
    remote_apple_events_enabled: bool | None = None
    remote_management_enabled: bool | None = None
    software_update: SoftwareUpdateSettingsData | None = None
    xprotect_version: str | None = None
    xprotect_remediator_version: str | None = None
    mrt_version: str | None = None


class ProxySettingData(BaseModel):
    service: str
    kind: Literal["http", "https", "socks", "pac"]
    host: str | None = None
    port: int | None = None
    url: str | None = None


class HostsEntryData(BaseModel):
    address: str = Field(min_length=1)
    hostnames: list[str]


class NetworkConfigurationData(BaseModel):
    dns_servers: list[str] = Field(default_factory=list)
    search_domains: list[str] = Field(default_factory=list)
    proxies: list[ProxySettingData] = Field(default_factory=list)
    hosts_entries: list[HostsEntryData] = Field(default_factory=list)
