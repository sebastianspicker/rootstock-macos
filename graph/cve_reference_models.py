"""Reference model dataclasses for Rootstock CVE/ATT&CK catalog data."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CweReference:
    """A CWE weakness class reference."""

    cwe_id: str       # "CWE-416"
    name: str         # "Use After Free"
    category: str = "other"  # "memory_safety", "access_control", "input_validation", etc.


@dataclass(frozen=True)
class CveEntry:
    """A single CVE record with scoring and patch metadata."""

    cve_id: str
    title: str
    cvss_score: float
    affected_versions: str
    patched_version: str | None
    description: str
    reference_url: str
    exploitation_status: str = "theoretical"  # "actively_exploited" | "poc_available" | "theoretical"
    attack_complexity: str = "medium"          # "low" | "medium" | "high"
    cwe_ids: tuple[str, ...] = ()             # CWE weakness class IDs
    affected_bundle_ids: tuple[str, ...] = ()  # e.g. ("com.apple.Safari",) for precise matching
    max_affected_version: str | None = None    # parseable version ceiling for precise matching


@dataclass(frozen=True)
class AttackTechnique:
    """A MITRE ATT&CK technique reference."""

    technique_id: str
    name: str
    tactic: str


@dataclass(frozen=True)
class ThreatGroup:
    """A MITRE ATT&CK threat group / APT actor."""

    group_id: str              # "G0096"
    name: str                  # "APT41"
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttackContext:
    """Full attack context for a Rootstock finding category."""

    category: str
    techniques: list[AttackTechnique]
    cves: list[CveEntry]
    remediation_priority: str  # "Immediate" | "High" | "Medium"


__all__ = [
    "AttackContext",
    "AttackTechnique",
    "CveEntry",
    "CweReference",
    "ThreatGroup",
]
