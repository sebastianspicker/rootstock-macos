"""Core static CVE entries for the Rootstock reference catalog."""

from __future__ import annotations

from cve_reference_models import CveEntry


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


__all__ = [
    '_CVE_2025_31191',
    '_CVE_2024_44168',
    '_CVE_2024_44133',
    '_CVE_2024_44131',
    '_CVE_2024_54498',
    '_CVE_2023_44402',
    '_CVE_2024_44243',
    '_CVE_2024_44294',
    '_CVE_2024_44217',
    '_CVE_2024_40781',
    '_CVE_2024_44206',
    '_CVE_2023_42937',
    '_CVE_2024_44245',
    '_CVE_2024_44204',
    '_CVE_2025_24085',
    '_CVE_2025_24118',
    '_CVE_2023_42861',
]
