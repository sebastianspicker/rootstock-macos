"""
cve_reference.py — CVE and MITRE ATT&CK reference registry for Rootstock findings.

Maps Rootstock finding categories to real-world CVEs (2023-2025) and ATT&CK techniques,
enabling prioritised vulnerability context in reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Registry version — bump when CVE/ATT&CK/CWE entries are added or modified.
# Imported by import_vulnerabilities.py and embedded in graph metadata.
REGISTRY_VERSION = "2026-03-21"

_VALID_EXPLOITATION_STATUSES = {"actively_exploited", "poc_available", "theoretical"}
_VALID_ATTACK_COMPLEXITIES = {"low", "medium", "high"}


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


# ── CVE Registry ─────────────────────────────────────────────────────────────

_CVE_2025_31191 = CveEntry(
    cve_id="CVE-2025-31191",
    title="AuthKit Keychain Injection via DYLD",
    cvss_score=8.8,
    affected_versions="macOS 15.3 and earlier",
    patched_version="macOS 15.4",
    description=(
        "A logic flaw in AuthKit allowed an attacker to inject a dylib into "
        "the AuthKit process and access keychain credentials without user consent."
    ),
    reference_url="https://support.apple.com/en-us/122373",
    cwe_ids=("CWE-427",),  # Uncontrolled Search Path Element
)

_CVE_2024_44168 = CveEntry(
    cve_id="CVE-2024-44168",
    title="Library Validation Bypass",
    cvss_score=7.5,
    affected_versions="macOS 14.6 and earlier",
    patched_version="macOS 14.7",
    description=(
        "A library validation bypass allowed an attacker to load unsigned "
        "dylibs into processes with library validation enabled."
    ),
    reference_url="https://support.apple.com/en-us/121238",
    cwe_ids=("CWE-347",),  # Improper Verification of Cryptographic Signature
)

_CVE_2024_44133 = CveEntry(
    cve_id="CVE-2024-44133",
    title="HM Surf — Safari TCC Bypass",
    cvss_score=8.8,
    affected_versions="macOS 14.6 and earlier",
    patched_version="macOS 15",
    description=(
        "Removing TCC protection for the Safari browser directory enabled "
        "an attacker to bypass TCC, access camera/microphone, and exfiltrate "
        "browsing data without user consent."
    ),
    reference_url="https://support.apple.com/en-us/121238",
    exploitation_status="actively_exploited",
    cwe_ids=("CWE-863",),  # Incorrect Authorization
    affected_bundle_ids=("com.apple.Safari",),
    max_affected_version="14.6",
)

_CVE_2024_44131 = CveEntry(
    cve_id="CVE-2024-44131",
    title="Files.app TCC Bypass via Symlink",
    cvss_score=7.5,
    affected_versions="macOS 15 and earlier, iOS 18 and earlier",
    patched_version="macOS 15.1",
    description=(
        "A symlink handling flaw in Files.app allowed a malicious app to "
        "access sensitive user data by intercepting file operations."
    ),
    reference_url="https://support.apple.com/en-us/121564",
    cwe_ids=("CWE-59",),  # Improper Link Resolution Before File Access
    affected_bundle_ids=("com.apple.finder",),
    max_affected_version="15",
)

_CVE_2024_54498 = CveEntry(
    cve_id="CVE-2024-54498",
    title="Sandbox Escape via App Sandbox",
    cvss_score=8.2,
    affected_versions="macOS 15.1 and earlier",
    patched_version="macOS 15.2",
    description=(
        "A path handling issue allowed a sandboxed application to escape "
        "its sandbox and access arbitrary files on the system."
    ),
    reference_url="https://support.apple.com/en-us/121839",
    exploitation_status="poc_available",
    cwe_ids=("CWE-22",),  # Path Traversal
)

_CVE_2023_44402 = CveEntry(
    cve_id="CVE-2023-44402",
    title="Electron contextIsolation Bypass",
    cvss_score=7.5,
    affected_versions="Electron < 27.1.0",
    patched_version="Electron 27.1.0",
    description=(
        "A bypass of Electron's contextIsolation protection allowed code "
        "running in the renderer process to access Node.js APIs."
    ),
    reference_url="https://github.com/nicedayzhu/Electron-CVE-2023-44402",
    cwe_ids=("CWE-668",),  # Exposure of Resource to Wrong Sphere
    # No specific bundle_ids — affects any Electron app; matched via category
)

_CVE_2024_44243 = CveEntry(
    cve_id="CVE-2024-44243",
    title="StorageKit SIP Bypass",
    cvss_score=9.8,
    affected_versions="macOS 15.1 and earlier",
    patched_version="macOS 15.2",
    description=(
        "A flaw in StorageKit allowed a locally authenticated attacker to "
        "bypass System Integrity Protection and modify protected system files."
    ),
    reference_url="https://support.apple.com/en-us/121839",
    cwe_ids=("CWE-284",),  # Improper Access Control
)

_CVE_2024_44294 = CveEntry(
    cve_id="CVE-2024-44294",
    title="PackageKit SIP Bypass",
    cvss_score=7.8,
    affected_versions="macOS 14.7 and earlier",
    patched_version="macOS 14.7.1",
    description=(
        "A logic issue in PackageKit allowed a malicious installer to "
        "modify SIP-protected directories during package installation."
    ),
    reference_url="https://support.apple.com/en-us/121570",
    cwe_ids=("CWE-284",),  # Improper Access Control
)

_CVE_2024_44217 = CveEntry(
    cve_id="CVE-2024-44217",
    title="LaunchServices Permission Bypass",
    cvss_score=7.5,
    affected_versions="macOS 14.7 and earlier",
    patched_version="macOS 15",
    description=(
        "A permissions issue in LaunchServices allowed an app to bypass "
        "certain Privacy preferences and access restricted data."
    ),
    reference_url="https://support.apple.com/en-us/121238",
    cwe_ids=("CWE-276",),  # Incorrect Default Permissions
)

_CVE_2024_40781 = CveEntry(
    cve_id="CVE-2024-40781",
    title="XPC Privilege Escalation",
    cvss_score=7.8,
    affected_versions="macOS 14.5 and earlier",
    patched_version="macOS 14.6",
    description=(
        "Insufficient XPC message validation allowed a local attacker to "
        "escalate privileges via a crafted XPC message to a privileged service."
    ),
    reference_url="https://support.apple.com/en-us/120911",
    cwe_ids=("CWE-20",),  # Improper Input Validation
)

_CVE_2024_44206 = CveEntry(
    cve_id="CVE-2024-44206",
    title="Finder AppleScript Execution",
    cvss_score=7.5,
    affected_versions="macOS 14.7 and earlier",
    patched_version="macOS 15",
    description=(
        "Finder could be scripted via Apple Events to perform file operations "
        "with the Finder's elevated TCC grants, enabling transitive FDA access."
    ),
    reference_url="https://support.apple.com/en-us/121238",
    cwe_ids=("CWE-862",),  # Missing Authorization
    affected_bundle_ids=("com.apple.finder",),
    max_affected_version="14.7",
)

_CVE_2023_42937 = CveEntry(
    cve_id="CVE-2023-42937",
    title="Accessibility Information Disclosure",
    cvss_score=5.5,
    affected_versions="macOS 14.2 and earlier",
    patched_version="macOS 14.3",
    description=(
        "A privacy issue in Accessibility allowed an app to access sensitive "
        "user data through the Accessibility framework."
    ),
    reference_url="https://support.apple.com/en-us/120896",
    cwe_ids=("CWE-200",),  # Exposure of Sensitive Information
)

_CVE_2024_44245 = CveEntry(
    cve_id="CVE-2024-44245",
    title="Kerberos ccache Race Condition",
    cvss_score=7.0,
    affected_versions="macOS 15.1 and earlier",
    patched_version="macOS 15.2",
    description=(
        "A race condition in Kerberos credential cache handling allowed "
        "a local attacker to read another user's ccache and impersonate them."
    ),
    reference_url="https://support.apple.com/en-us/121839",
    cwe_ids=("CWE-362",),  # Race Condition
)

_CVE_2024_44204 = CveEntry(
    cve_id="CVE-2024-44204",
    title="Keychain Unauthorized Credential Access",
    cvss_score=7.5,
    affected_versions="macOS 14.7 and earlier",
    patched_version="macOS 15",
    description=(
        "A logic issue allowed an application to access keychain items "
        "without the expected user prompt for credential access."
    ),
    reference_url="https://support.apple.com/en-us/121238",
    cwe_ids=("CWE-862",),  # Missing Authorization
)

_CVE_2025_24085 = CveEntry(
    cve_id="CVE-2025-24085",
    title="CoreMedia Use-After-Free (Actively Exploited)",
    cvss_score=9.8,
    affected_versions="macOS 15.2 and earlier",
    patched_version="macOS 15.3",
    description=(
        "A use-after-free in CoreMedia allowed a malicious application "
        "to elevate privileges. Apple confirmed active exploitation in the wild."
    ),
    reference_url="https://support.apple.com/en-us/122066",
    exploitation_status="actively_exploited",
    cwe_ids=("CWE-416",),  # Use After Free
)

_CVE_2025_24118 = CveEntry(
    cve_id="CVE-2025-24118",
    title="Kernel Race Condition Privilege Escalation",
    cvss_score=9.0,
    affected_versions="macOS 15.2 and earlier",
    patched_version="macOS 15.3",
    description=(
        "A race condition in the XNU kernel allowed a local attacker "
        "to escalate privileges to kernel level."
    ),
    reference_url="https://support.apple.com/en-us/122066",
    cwe_ids=("CWE-362",),  # Race Condition
)

_CVE_2023_42861 = CveEntry(
    cve_id="CVE-2023-42861",
    title="Login Screen Bypass",
    cvss_score=6.5,
    affected_versions="macOS 14.0 and earlier",
    patched_version="macOS 14.1",
    description=(
        "A logic issue allowed a local attacker to bypass the login screen "
        "and access the desktop without valid credentials under certain conditions."
    ),
    reference_url="https://support.apple.com/en-us/120895",
    cwe_ids=("CWE-287",),  # Improper Authentication
)

# ── New CVE Entries (high-impact, actively exploited, or overlooked) ─────────

_CVE_2023_41064 = CveEntry(
    cve_id="CVE-2023-41064",
    title="BLASTPASS — ImageIO Buffer Overflow",
    cvss_score=7.8,
    affected_versions="macOS 13.5 and earlier, iOS 16.6 and earlier",
    patched_version="macOS 13.5.2, iOS 16.6.1",
    description=(
        "A buffer overflow in ImageIO allowed remote code execution via a "
        "crafted image. Exploited as part of the BLASTPASS zero-click chain "
        "to deploy NSO Group Pegasus spyware."
    ),
    reference_url="https://support.apple.com/en-us/119060",
    exploitation_status="actively_exploited",
    attack_complexity="high",
    cwe_ids=("CWE-120",),  # Buffer Overflow
)

_CVE_2023_41061 = CveEntry(
    cve_id="CVE-2023-41061",
    title="BLASTPASS — Wallet Validation Issue",
    cvss_score=7.8,
    affected_versions="macOS 13.5 and earlier, iOS 16.6 and earlier",
    patched_version="macOS 13.5.2, iOS 16.6.1",
    description=(
        "A validation issue in Wallet allowed arbitrary code execution via a "
        "malicious attachment. Used alongside CVE-2023-41064 in the BLASTPASS "
        "zero-click exploit chain."
    ),
    reference_url="https://support.apple.com/en-us/119060",
    exploitation_status="actively_exploited",
    attack_complexity="high",
    cwe_ids=("CWE-20",),  # Improper Input Validation
)

_CVE_2023_38606 = CveEntry(
    cve_id="CVE-2023-38606",
    title="Kernel Sandbox Bypass (Operation Triangulation)",
    cvss_score=8.6,
    affected_versions="macOS 13.4 and earlier, iOS 16.5 and earlier",
    patched_version="macOS 13.5, iOS 16.6",
    description=(
        "A kernel vulnerability allowed an app to modify sensitive kernel state "
        "and escape the sandbox. Exploited in the Operation Triangulation APT "
        "campaign targeting iMessage."
    ),
    reference_url="https://support.apple.com/en-us/118736",
    exploitation_status="actively_exploited",
    attack_complexity="high",
    cwe_ids=("CWE-284",),  # Improper Access Control
)

_CVE_2023_32414 = CveEntry(
    cve_id="CVE-2023-32414",
    title="Sandbox Escape via Symlink Race (Pwn2Own)",
    cvss_score=8.6,
    affected_versions="macOS 13.3 and earlier",
    patched_version="macOS 13.4",
    description=(
        "A race condition in sandbox path validation allowed a sandboxed app "
        "to escape its container via symlink manipulation. Demonstrated at "
        "Pwn2Own Vancouver 2023."
    ),
    reference_url="https://support.apple.com/en-us/118695",
    exploitation_status="poc_available",
    attack_complexity="high",
    cwe_ids=("CWE-362", "CWE-59"),  # Race Condition + Symlink Following
)

_CVE_2024_23296 = CveEntry(
    cve_id="CVE-2024-23296",
    title="RTKit Kernel Memory Corruption",
    cvss_score=7.8,
    affected_versions="macOS 14.3 and earlier, iOS 17.3 and earlier",
    patched_version="macOS 14.4, iOS 17.4",
    description=(
        "A memory corruption issue in RTKit allowed an attacker with arbitrary "
        "kernel read/write to bypass kernel memory protections. Apple confirmed "
        "active exploitation in the wild."
    ),
    reference_url="https://support.apple.com/en-us/120895",
    exploitation_status="actively_exploited",
    cwe_ids=("CWE-787",),  # Out-of-bounds Write
)

_CVE_2023_40404 = CveEntry(
    cve_id="CVE-2023-40404",
    title="IOSurface Use-After-Free",
    cvss_score=7.8,
    affected_versions="macOS 14.0 and earlier",
    patched_version="macOS 14.1",
    description=(
        "A use-after-free in IOSurface allowed a local attacker to execute "
        "arbitrary code with kernel privileges."
    ),
    reference_url="https://support.apple.com/en-us/120895",
    exploitation_status="poc_available",
    cwe_ids=("CWE-416",),  # Use After Free
)

_CVE_2024_27842 = CveEntry(
    cve_id="CVE-2024-27842",
    title="IOKit Privilege Escalation (EDR Bypass Vector)",
    cvss_score=7.8,
    affected_versions="macOS 14.4 and earlier",
    patched_version="macOS 14.5",
    description=(
        "An IOKit vulnerability allowed a local attacker to escalate privileges "
        "to kernel level, potentially bypassing Endpoint Security Framework "
        "monitoring."
    ),
    reference_url="https://support.apple.com/en-us/120903",
    exploitation_status="poc_available",
    cwe_ids=("CWE-269",),  # Improper Privilege Management
)

_CVE_2023_41990 = CveEntry(
    cve_id="CVE-2023-41990",
    title="FontParser Code Execution (Operation Triangulation)",
    cvss_score=7.8,
    affected_versions="macOS 13.5 and earlier, iOS 16.5 and earlier",
    patched_version="macOS 14, iOS 16.7",
    description=(
        "A font parsing vulnerability allowed remote code execution via a "
        "crafted font file. Exploited as part of the Operation Triangulation "
        "zero-click iMessage chain."
    ),
    reference_url="https://support.apple.com/en-us/119060",
    exploitation_status="actively_exploited",
    attack_complexity="high",
    cwe_ids=("CWE-122",),  # Heap-based Buffer Overflow
)

_CVE_2022_42821 = CveEntry(
    cve_id="CVE-2022-42821",
    title="Gatekeeper Bypass (Achilles)",
    cvss_score=5.5,
    affected_versions="macOS 13.0 and earlier",
    patched_version="macOS 13.1",
    description=(
        "A logic issue in Gatekeeper allowed a downloaded application to bypass "
        "Gatekeeper checks via restrictive ACLs that prevented quarantine "
        "attribute propagation (Achilles vulnerability)."
    ),
    reference_url="https://support.apple.com/en-us/113736",
    exploitation_status="actively_exploited",
    attack_complexity="low",
    cwe_ids=("CWE-693",),  # Protection Mechanism Failure
)

_CVE_2024_44175 = CveEntry(
    cve_id="CVE-2024-44175",
    title="File Quarantine Bypass",
    cvss_score=7.5,
    affected_versions="macOS 14.6 and earlier",
    patched_version="macOS 14.7",
    description=(
        "A logic issue allowed downloaded files to bypass file quarantine "
        "enforcement, enabling unvetted code execution without Gatekeeper "
        "prompts."
    ),
    reference_url="https://support.apple.com/en-us/121238",
    exploitation_status="poc_available",
    cwe_ids=("CWE-693",),  # Protection Mechanism Failure
)

_CVE_2023_45866 = CveEntry(
    cve_id="CVE-2023-45866",
    title="Bluetooth Keystroke Injection (Cross-Platform)",
    cvss_score=6.3,
    affected_versions="macOS 14.1 and earlier, multiple platforms",
    patched_version="macOS 14.2",
    description=(
        "A Bluetooth HID vulnerability allowed an attacker in physical proximity "
        "to inject keystrokes into a paired device without user confirmation. "
        "Affects macOS, iOS, Linux, and Android."
    ),
    reference_url="https://support.apple.com/en-us/120896",
    exploitation_status="actively_exploited",
    attack_complexity="low",
    cwe_ids=("CWE-287",),  # Improper Authentication
)

_CVE_2025_24200 = CveEntry(
    cve_id="CVE-2025-24200",
    title="USB Restricted Mode Bypass",
    cvss_score=6.1,
    affected_versions="macOS 15.3 and earlier, iOS 18.3 and earlier",
    patched_version="macOS 15.3.1, iOS 18.3.1",
    description=(
        "An authorization issue allowed a physical attacker to disable USB "
        "Restricted Mode on a locked device, enabling data extraction via "
        "forensic tools."
    ),
    reference_url="https://support.apple.com/en-us/122174",
    exploitation_status="actively_exploited",
    attack_complexity="low",
    cwe_ids=("CWE-863",),  # Incorrect Authorization
)

_CVE_2025_24201 = CveEntry(
    cve_id="CVE-2025-24201",
    title="WebKit Out-of-Bounds Write",
    cvss_score=8.8,
    affected_versions="macOS 15.3 and earlier, iOS 18.3 and earlier",
    patched_version="macOS 15.3.2, iOS 18.3.2",
    description=(
        "An out-of-bounds write in WebKit allowed crafted web content to "
        "escape the Web Content sandbox. Apple confirmed exploitation in "
        "sophisticated targeted attacks."
    ),
    reference_url="https://support.apple.com/en-us/122281",
    exploitation_status="actively_exploited",
    attack_complexity="high",
    cwe_ids=("CWE-787",),  # Out-of-bounds Write
    affected_bundle_ids=("com.apple.Safari",),
    max_affected_version="17.3.2",
)

_CVE_2023_32364 = CveEntry(
    cve_id="CVE-2023-32364",
    title="Terminal .zshrc Injection",
    cvss_score=7.8,
    affected_versions="macOS 13.3 and earlier",
    patched_version="macOS 13.4",
    description=(
        "A path handling issue in Terminal allowed a malicious app to write "
        "to the user's .zshrc, enabling persistent code execution in every "
        "new shell session."
    ),
    reference_url="https://support.apple.com/en-us/118695",
    exploitation_status="poc_available",
    cwe_ids=("CWE-22",),  # Path Traversal
    affected_bundle_ids=("com.apple.Terminal",),
)

_CVE_2024_44301 = CveEntry(
    cve_id="CVE-2024-44301",
    title="MDM Profile Handling Issue",
    cvss_score=6.5,
    affected_versions="macOS 14.7 and earlier",
    patched_version="macOS 15",
    description=(
        "A logic issue in MDM profile handling allowed a managed configuration "
        "profile to grant broader TCC permissions than intended to scripting "
        "interpreters."
    ),
    reference_url="https://support.apple.com/en-us/121238",
    cwe_ids=("CWE-269",),  # Improper Privilege Management
)

_CVE_2023_42926 = CveEntry(
    cve_id="CVE-2023-42926",
    title="Sandbox Escape → iCloud Container Read",
    cvss_score=7.5,
    affected_versions="macOS 14.1 and earlier",
    patched_version="macOS 14.2",
    description=(
        "A sandbox escape allowed a malicious app to read iCloud container "
        "data belonging to other applications, enabling cross-app data theft "
        "via iCloud sync."
    ),
    reference_url="https://support.apple.com/en-us/120896",
    exploitation_status="poc_available",
    cwe_ids=("CWE-22",),  # Path Traversal
)

_CVE_2024_49019 = CveEntry(
    cve_id="CVE-2024-49019",
    title="AD Certificate Services Abuse (Certifried)",
    cvss_score=7.5,
    affected_versions="Windows Server 2012–2022, affects AD-bound macOS",
    patched_version="November 2024 Patch Tuesday",
    description=(
        "Active Directory Certificate Services allowed an authenticated user "
        "to escalate privileges to domain admin by abusing certificate template "
        "misconfigurations. Affects macOS clients bound to vulnerable AD domains."
    ),
    reference_url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019",
    exploitation_status="poc_available",
    cwe_ids=("CWE-269",),  # Improper Privilege Management
)

_CVE_2023_35389 = CveEntry(
    cve_id="CVE-2023-35389",
    title="AD Delegation Abuse",
    cvss_score=7.5,
    affected_versions="Windows Server 2012–2022, affects AD-bound macOS",
    patched_version="August 2023 Patch Tuesday",
    description=(
        "A flaw in Active Directory delegation handling allowed an attacker "
        "to impersonate privileged accounts via constrained delegation abuse. "
        "AD-bound macOS clients are affected when using Kerberos authentication."
    ),
    reference_url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35389",
    cwe_ids=("CWE-269",),  # Improper Privilege Management
)

# ── ATT&CK Technique Registry ────────────────────────────────────────────────

_T1574_006 = AttackTechnique(
    technique_id="T1574.006",
    name="Dynamic Linker Hijacking",
    tactic="Persistence, Privilege Escalation",
)

_T1548_004 = AttackTechnique(
    technique_id="T1548.004",
    name="Elevated Execution with Prompt",
    tactic="Privilege Escalation, Defense Evasion",
)

_T1059_007 = AttackTechnique(
    technique_id="T1059.007",
    name="JavaScript",
    tactic="Execution",
)

_T1562_001 = AttackTechnique(
    technique_id="T1562.001",
    name="Disable or Modify Tools",
    tactic="Defense Evasion",
)

_T1547_011 = AttackTechnique(
    technique_id="T1547.011",
    name="Plist Modification",
    tactic="Persistence, Privilege Escalation",
)

_T1543_004 = AttackTechnique(
    technique_id="T1543.004",
    name="Launch Daemon",
    tactic="Persistence, Privilege Escalation",
)

_T1559_001 = AttackTechnique(
    technique_id="T1559.001",
    name="Component Object Model",
    tactic="Execution",
)

_T1059_002 = AttackTechnique(
    technique_id="T1059.002",
    name="AppleScript",
    tactic="Execution",
)

_T1056_002 = AttackTechnique(
    technique_id="T1056.002",
    name="GUI Input Capture",
    tactic="Collection, Credential Access",
)

_T1558 = AttackTechnique(
    technique_id="T1558",
    name="Steal or Forge Kerberos Tickets",
    tactic="Credential Access",
)

_T1555_001 = AttackTechnique(
    technique_id="T1555.001",
    name="Keychain",
    tactic="Credential Access",
)

_T1068 = AttackTechnique(
    technique_id="T1068",
    name="Exploitation for Privilege Escalation",
    tactic="Privilege Escalation",
)

_T1548_003 = AttackTechnique(
    technique_id="T1548.003",
    name="Sudo and Sudo Caching",
    tactic="Privilege Escalation, Defense Evasion",
)

_T1200 = AttackTechnique(
    technique_id="T1200",
    name="Hardware Additions",
    tactic="Initial Access",
)

_T1537 = AttackTechnique(
    technique_id="T1537",
    name="Transfer Data to Cloud Account",
    tactic="Exfiltration",
)

# ── New ATT&CK Techniques ───────────────────────────────────────────────────

_T1546_004 = AttackTechnique(
    technique_id="T1546.004",
    name="Unix Shell Configuration Modification",
    tactic="Persistence, Privilege Escalation",
)

_T1553_001 = AttackTechnique(
    technique_id="T1553.001",
    name="Gatekeeper Bypass",
    tactic="Defense Evasion",
)

_T1556_001 = AttackTechnique(
    technique_id="T1556.001",
    name="Modify Authentication Process",
    tactic="Credential Access",
)

_T1021_004 = AttackTechnique(
    technique_id="T1021.004",
    name="Remote Services: SSH",
    tactic="Lateral Movement",
)

_T1021_005 = AttackTechnique(
    technique_id="T1021.005",
    name="Remote Services: VNC",
    tactic="Lateral Movement",
)

_T1014 = AttackTechnique(
    technique_id="T1014",
    name="Rootkit",
    tactic="Defense Evasion",
)

_T1098 = AttackTechnique(
    technique_id="T1098",
    name="Account Manipulation",
    tactic="Persistence, Privilege Escalation",
)

_T1190 = AttackTechnique(
    technique_id="T1190",
    name="Exploit Public-Facing Application",
    tactic="Initial Access",
)

_T1556_003 = AttackTechnique(
    technique_id="T1556.003",
    name="Pluggable Authentication Modules",
    tactic="Credential Access",
)

_T1612 = AttackTechnique(
    technique_id="T1612",
    name="Build Image on Host",
    tactic="Defense Evasion",
)

# ── Attack Context Registry ──────────────────────────────────────────────────

_REGISTRY: dict[str, AttackContext] = {
    "dyld_injection": AttackContext(
        category="dyld_injection",
        techniques=[_T1574_006],
        cves=[_CVE_2025_31191, _CVE_2024_44168],
        remediation_priority="Immediate",
    ),
    "injectable_fda": AttackContext(
        category="injectable_fda",
        techniques=[_T1574_006],
        cves=[_CVE_2025_31191, _CVE_2024_44168],
        remediation_priority="Immediate",
    ),
    "tcc_bypass": AttackContext(
        category="tcc_bypass",
        techniques=[_T1548_004],
        cves=[_CVE_2024_44133, _CVE_2024_44131, _CVE_2024_54498],
        remediation_priority="Immediate",
    ),
    "electron_inheritance": AttackContext(
        category="electron_inheritance",
        techniques=[_T1574_006, _T1059_007],
        cves=[_CVE_2023_44402],
        remediation_priority="High",
    ),
    "sip_bypass": AttackContext(
        category="sip_bypass",
        techniques=[_T1562_001],
        cves=[_CVE_2024_44243, _CVE_2024_44294],
        remediation_priority="Immediate",
    ),
    "persistence_hijack": AttackContext(
        category="persistence_hijack",
        techniques=[_T1547_011, _T1543_004],
        cves=[_CVE_2024_44217],
        remediation_priority="High",
    ),
    "xpc_exploitation": AttackContext(
        category="xpc_exploitation",
        techniques=[_T1559_001],
        cves=[_CVE_2024_40781],
        remediation_priority="High",
    ),
    "apple_events": AttackContext(
        category="apple_events",
        techniques=[_T1059_002],
        cves=[_CVE_2024_44206],
        remediation_priority="High",
    ),
    "accessibility_abuse": AttackContext(
        category="accessibility_abuse",
        techniques=[_T1056_002],
        cves=[_CVE_2023_42937],
        remediation_priority="High",
    ),
    "kerberos": AttackContext(
        category="kerberos",
        techniques=[_T1558, _T1556_003],
        cves=[_CVE_2024_44245, _CVE_2024_49019, _CVE_2023_35389],
        remediation_priority="High",
    ),
    "keychain_access": AttackContext(
        category="keychain_access",
        techniques=[_T1555_001],
        cves=[_CVE_2024_44204],
        remediation_priority="High",
    ),
    "kernel_escalation": AttackContext(
        category="kernel_escalation",
        techniques=[_T1068],
        cves=[_CVE_2025_24085, _CVE_2025_24118],
        remediation_priority="Immediate",
    ),
    "authorization_hardening": AttackContext(
        category="authorization_hardening",
        techniques=[_T1548_003],
        cves=[],
        remediation_priority="Medium",
    ),
    "physical_security": AttackContext(
        category="physical_security",
        techniques=[_T1200],
        cves=[_CVE_2023_42861, _CVE_2023_45866, _CVE_2025_24200],
        remediation_priority="Medium",
    ),
    "icloud_risk": AttackContext(
        category="icloud_risk",
        techniques=[_T1537],
        cves=[_CVE_2023_42926],
        remediation_priority="Medium",
    ),
    # ── New categories ──────────────────────────────────────────────────────
    "certificate_hygiene": AttackContext(
        category="certificate_hygiene",
        techniques=[_T1553_001],
        cves=[_CVE_2022_42821, _CVE_2024_44175],
        remediation_priority="High",
    ),
    "shell_hooks": AttackContext(
        category="shell_hooks",
        techniques=[_T1546_004],
        cves=[_CVE_2023_32364],
        remediation_priority="High",
    ),
    "file_acl_escalation": AttackContext(
        category="file_acl_escalation",
        techniques=[_T1098],
        cves=[_CVE_2024_44131, _CVE_2024_44133],
        remediation_priority="Immediate",
    ),
    "esf_bypass": AttackContext(
        category="esf_bypass",
        techniques=[_T1014, _T1562_001],
        cves=[_CVE_2024_27842, _CVE_2023_41990],
        remediation_priority="Immediate",
    ),
    "sandbox_escape": AttackContext(
        category="sandbox_escape",
        techniques=[_T1612],
        cves=[_CVE_2023_32414, _CVE_2023_38606],
        remediation_priority="Immediate",
    ),
    "mdm_risk": AttackContext(
        category="mdm_risk",
        techniques=[_T1548_004],
        cves=[_CVE_2024_44301],
        remediation_priority="High",
    ),
    "lateral_movement": AttackContext(
        category="lateral_movement",
        techniques=[_T1021_004, _T1021_005],
        cves=[],
        remediation_priority="High",
    ),
    "running_processes": AttackContext(
        category="running_processes",
        techniques=[_T1574_006],
        cves=[_CVE_2025_24085, _CVE_2025_24201],
        remediation_priority="Immediate",
    ),
    "auth_plugin_risk": AttackContext(
        category="auth_plugin_risk",
        techniques=[_T1556_001],
        cves=[],
        remediation_priority="High",
    ),
    "blastpass_class": AttackContext(
        category="blastpass_class",
        techniques=[_T1068],
        cves=[_CVE_2023_41064, _CVE_2023_41061],
        remediation_priority="Immediate",
    ),
    "firewall_exposure": AttackContext(
        category="firewall_exposure",
        techniques=[_T1190],
        cves=[],
        remediation_priority="High",
    ),
    "gatekeeper_bypass": AttackContext(
        category="gatekeeper_bypass",
        techniques=[_T1553_001],
        cves=[_CVE_2022_42821, _CVE_2024_44175],
        remediation_priority="High",
    ),
}


# ── Threat Group Registry ────────────────────────────────────────────────────

_GROUP_REGISTRY: dict[str, ThreatGroup] = {
    "G0096": ThreatGroup("G0096", "APT41", aliases=("Winnti", "Barium")),
    "G0032": ThreatGroup("G0032", "Lazarus Group", aliases=("Hidden Cobra", "ZINC")),
    "G0050": ThreatGroup("G0050", "OceanLotus", aliases=("APT32",)),
    "G0046": ThreatGroup("G0046", "FIN7", aliases=("Carbanak",)),
    "G0010": ThreatGroup("G0010", "Turla", aliases=("Snake", "Venomous Bear")),
    "G0016": ThreatGroup("G0016", "APT29", aliases=("Cozy Bear", "Nobelium")),
    "G0007": ThreatGroup("G0007", "APT28", aliases=("Fancy Bear", "Sofacy")),
    "G0094": ThreatGroup("G0094", "Kimsuky", aliases=("Velvet Chollima",)),
    "G9001": ThreatGroup("G9001", "Operation Triangulation", aliases=()),
    "G9002": ThreatGroup("G9002", "NSO Group (Pegasus)", aliases=("Pegasus",)),
}

# Maps each group to the ATT&CK techniques it is known to use (from the
# techniques already defined above).
_GROUP_TECHNIQUE_MAP: dict[str, list[str]] = {
    "G0096": ["T1574.006", "T1068", "T1059.007"],           # APT41
    "G0032": ["T1574.006", "T1068"],                         # Lazarus
    "G0050": ["T1574.006", "T1059.002", "T1547.011"],        # OceanLotus
    "G0046": ["T1059.007", "T1574.006"],                     # FIN7
    "G0010": ["T1574.006", "T1543.004", "T1059.002"],        # Turla
    "G0016": ["T1574.006", "T1555.001", "T1098"],            # APT29
    "G0007": ["T1068", "T1190", "T1059.007"],                # APT28
    "G0094": ["T1059.002", "T1547.011"],                     # Kimsuky
    "G9001": ["T1068"],                                       # Operation Triangulation
    "G9002": ["T1068", "T1200"],                              # NSO Group / Pegasus
}


# ── Public API ────────────────────────────────────────────────────────────────

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d+")


def get_context(category: str) -> AttackContext | None:
    """Return the AttackContext for a finding category, or None if unknown."""
    return _REGISTRY.get(category)


def get_contexts_for_query(query: dict) -> list[AttackContext]:
    """
    Return AttackContexts relevant to a query descriptor.

    Looks up by CVE IDs in the query's ``cve`` field, matching against
    all registry entries.
    """
    cve_field = query.get("cve", "")
    if not cve_field:
        return []

    query_cves = set(_CVE_ID_RE.findall(cve_field))
    if not query_cves:
        return []

    matches: list[AttackContext] = []
    for ctx in _REGISTRY.values():
        ctx_cves = {c.cve_id for c in ctx.cves}
        if ctx_cves & query_cves:
            matches.append(ctx)
    return matches


def get_all_critical_cves(min_cvss: float = 8.0) -> list[CveEntry]:
    """Return all CVEs at or above *min_cvss*, sorted by CVSS descending."""
    seen: set[str] = set()
    result: list[CveEntry] = []
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            if cve.cvss_score >= min_cvss and cve.cve_id not in seen:
                seen.add(cve.cve_id)
                result.append(cve)
    result.sort(key=lambda c: c.cvss_score, reverse=True)
    return result


# ── CWE Reference Lookup ────────────────────────────────────────────────────

# Master CWE reference table — maps CWE IDs to human-readable names.
CWE_REGISTRY: dict[str, CweReference] = {
    "CWE-20":  CweReference("CWE-20",  "Improper Input Validation",                      "input_validation"),
    "CWE-22":  CweReference("CWE-22",  "Path Traversal",                                 "input_validation"),
    "CWE-59":  CweReference("CWE-59",  "Improper Link Resolution Before File Access",    "input_validation"),
    "CWE-120": CweReference("CWE-120", "Buffer Overflow",                                "memory_safety"),
    "CWE-122": CweReference("CWE-122", "Heap-based Buffer Overflow",                     "memory_safety"),
    "CWE-200": CweReference("CWE-200", "Exposure of Sensitive Information",               "information_disclosure"),
    "CWE-269": CweReference("CWE-269", "Improper Privilege Management",                   "access_control"),
    "CWE-276": CweReference("CWE-276", "Incorrect Default Permissions",                   "access_control"),
    "CWE-284": CweReference("CWE-284", "Improper Access Control",                         "access_control"),
    "CWE-287": CweReference("CWE-287", "Improper Authentication",                         "authentication"),
    "CWE-347": CweReference("CWE-347", "Improper Verification of Cryptographic Signature","authentication"),
    "CWE-362": CweReference("CWE-362", "Race Condition",                                  "concurrency"),
    "CWE-416": CweReference("CWE-416", "Use After Free",                                  "memory_safety"),
    "CWE-427": CweReference("CWE-427", "Uncontrolled Search Path Element",                "input_validation"),
    "CWE-668": CweReference("CWE-668", "Exposure of Resource to Wrong Sphere",            "access_control"),
    "CWE-693": CweReference("CWE-693", "Protection Mechanism Failure",                    "access_control"),
    "CWE-787": CweReference("CWE-787", "Out-of-bounds Write",                             "memory_safety"),
    "CWE-862": CweReference("CWE-862", "Missing Authorization",                           "access_control"),
    "CWE-863": CweReference("CWE-863", "Incorrect Authorization",                         "access_control"),
}


def get_cwe(cwe_id: str) -> CweReference | None:
    """Look up a CWE reference by ID."""
    return CWE_REGISTRY.get(cwe_id)


def get_cwe_summary() -> dict[str, int]:
    """Count CWE occurrences across all registry CVEs. Returns {cwe_id: count}."""
    counts: dict[str, int] = {}
    seen: set[str] = set()
    for ctx in _REGISTRY.values():
        for cve in ctx.cves:
            if cve.cve_id in seen:
                continue
            seen.add(cve.cve_id)
            for cwe_id in cve.cwe_ids:
                counts[cwe_id] = counts.get(cwe_id, 0) + 1
    return counts
