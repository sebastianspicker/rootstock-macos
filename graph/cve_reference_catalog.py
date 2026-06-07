"""Static ATT&CK context and threat-group catalog data for Rootstock."""

from __future__ import annotations

from cve_reference_cves_core import (
    _CVE_2025_31191,
    _CVE_2024_44168,
    _CVE_2024_44133,
    _CVE_2024_44131,
    _CVE_2024_54498,
    _CVE_2023_44402,
    _CVE_2024_44243,
    _CVE_2024_44294,
    _CVE_2024_44217,
    _CVE_2024_40781,
    _CVE_2024_44206,
    _CVE_2023_42937,
    _CVE_2024_44245,
    _CVE_2024_44204,
    _CVE_2025_24085,
    _CVE_2025_24118,
    _CVE_2023_42861,
)
from cve_reference_cves_extended import (
    _CVE_2023_41064,
    _CVE_2023_41061,
    _CVE_2023_38606,
    _CVE_2023_32414,
    _CVE_2024_27842,
    _CVE_2023_41990,
    _CVE_2022_42821,
    _CVE_2024_44175,
    _CVE_2023_45866,
    _CVE_2025_24200,
    _CVE_2025_24201,
    _CVE_2023_32364,
    _CVE_2024_44301,
    _CVE_2023_42926,
    _CVE_2024_49019,
    _CVE_2023_35389,
)
from cve_reference_models import AttackContext, AttackTechnique, ThreatGroup


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
