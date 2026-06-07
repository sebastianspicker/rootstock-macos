"""Extended static CVE entries for the Rootstock reference catalog."""

from __future__ import annotations

from cve_reference_models import CveEntry


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
    affected_versions="Windows Server 2012-2022, affects AD-bound macOS",
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
    affected_versions="Windows Server 2012-2022, affects AD-bound macOS",
    patched_version="August 2023 Patch Tuesday",
    description=(
        "A flaw in Active Directory delegation handling allowed an attacker "
        "to impersonate privileged accounts via constrained delegation abuse. "
        "AD-bound macOS clients are affected when using Kerberos authentication."
    ),
    reference_url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35389",
    cwe_ids=("CWE-269",),  # Improper Privilege Management
)


__all__ = [
    '_CVE_2023_41064',
    '_CVE_2023_41061',
    '_CVE_2023_38606',
    '_CVE_2023_32414',
    '_CVE_2024_23296',
    '_CVE_2023_40404',
    '_CVE_2024_27842',
    '_CVE_2023_41990',
    '_CVE_2022_42821',
    '_CVE_2024_44175',
    '_CVE_2023_45866',
    '_CVE_2025_24200',
    '_CVE_2025_24201',
    '_CVE_2023_32364',
    '_CVE_2024_44301',
    '_CVE_2023_42926',
    '_CVE_2024_49019',
    '_CVE_2023_35389',
]
