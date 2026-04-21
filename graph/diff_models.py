"""diff_models.py — Dataclasses for Rootstock posture diff results."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AppDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

@dataclass
class TCCDiff:
    added: list[dict] = field(default_factory=list)
    removed: list[dict] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)

@dataclass
class InjectionDiff:
    new_injectable: list[dict] = field(default_factory=list)
    no_longer_injectable: list[dict] = field(default_factory=list)
    methods_changed: list[dict] = field(default_factory=list)

@dataclass
class PersistenceDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

@dataclass
class EntitlementDiff:
    apps_gained_critical: list[dict] = field(default_factory=list)
    apps_lost_critical: list[dict] = field(default_factory=list)

@dataclass
class PhysicalPostureDiff:
    """Changes in physical security posture fields."""
    changes: dict[str, dict] = field(default_factory=dict)

@dataclass
class RemoteAccessDiff:
    """Changes in remote access services (ssh, screen_sharing)."""
    added: list[dict] = field(default_factory=list)
    removed: list[dict] = field(default_factory=list)
    changed: list[dict] = field(default_factory=list)

@dataclass
class ICloudPostureDiff:
    """Changes in iCloud posture fields."""
    changes: dict[str, dict] = field(default_factory=dict)

@dataclass
class VulnerabilityDiff:
    """Changes in CVE vulnerability associations between scans."""
    new_cve_associations: list[dict] = field(default_factory=list)
    resolved_cve_associations: list[dict] = field(default_factory=list)
    new_kev_entries: list[dict] = field(default_factory=list)

@dataclass
class PostureDiff:
    hostname: str = ""
    before_scan_id: str = ""
    after_scan_id: str = ""
    before_timestamp: str = ""
    after_timestamp: str = ""
    apps: AppDiff = field(default_factory=AppDiff)
    tcc: TCCDiff = field(default_factory=TCCDiff)
    injection: InjectionDiff = field(default_factory=InjectionDiff)
    persistence: PersistenceDiff = field(default_factory=PersistenceDiff)
    entitlements: EntitlementDiff = field(default_factory=EntitlementDiff)
    system_posture: dict = field(default_factory=dict)
    physical_posture: PhysicalPostureDiff = field(default_factory=PhysicalPostureDiff)
    remote_access: RemoteAccessDiff = field(default_factory=RemoteAccessDiff)
    icloud_posture: ICloudPostureDiff = field(default_factory=ICloudPostureDiff)
    vulnerability: VulnerabilityDiff = field(default_factory=VulnerabilityDiff)
