"""Shared Application category predicates for risk and vulnerability workflows."""

from __future__ import annotations

SHARED_CATEGORY_PREDICATES: dict[str, str] = {
    "injectable_fda": """
        EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: 'kTCCServiceSystemPolicyAllFiles'})
        }
        AND size(app.injection_methods) > 0
    """,
    "dyld_injection": """
        size(app.injection_methods) > 0
        AND any(m IN app.injection_methods WHERE m CONTAINS 'dyld')
    """,
    "tcc_bypass": """
        EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        }
    """,
    "sip_bypass": """
        EXISTS {
            MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement)
            WHERE app.team_id IS NOT NULL AND app.team_id <> 'com.apple'
        }
        AND size(app.injection_methods) > 0
    """,
    "persistence_hijack": """
        EXISTS {
            MATCH (app)-[:PERSISTS_VIA]->(li:LaunchItem)
            WHERE li.program_writable_by_non_root = true OR li.plist_writable_by_non_root = true
        }
    """,
    "xpc_exploitation": """
        EXISTS {
            MATCH (app)-[:COMMUNICATES_WITH]->(:XPC_Service)
        }
        AND size(app.injection_methods) > 0
    """,
    "apple_events": """
        EXISTS {
            MATCH (app)-[:CAN_SEND_APPLE_EVENT]->()
        }
    """,
    "accessibility_abuse": """
        EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission {service: 'kTCCServiceAccessibility'})
        }
        AND size(app.injection_methods) > 0
    """,
    "kerberos": """
        EXISTS {
            MATCH (app)-[:INSTALLED_ON]->(:Computer)<-[:LOCAL_TO]-(u:User)-[:HAS_KERBEROS_CACHE]->()
        }
        OR EXISTS {
            MATCH (app)-[:INSTALLED_ON]->(:Computer)<-[:LOCAL_TO]-(u:User)-[:HAS_KEYTAB]->()
        }
    """,
    "keychain_access": """
        EXISTS {
            MATCH (app)-[:CAN_READ_KEYCHAIN]->(:Keychain_Item)
        }
        AND size(app.injection_methods) > 0
    """,
    "kernel_escalation": """
        size(app.injection_methods) > 0
        AND EXISTS {
            MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement {is_private: true})
        }
    """,
    "certificate_hygiene": """
        app.signed = true
        AND (
            coalesce(app.is_certificate_expired, false) = true
            OR coalesce(app.is_adhoc_signed, false) = true
            OR app.certificate_trust_valid = false
        )
    """,
    "shell_hooks": """
        EXISTS {
            MATCH (app)-[:CAN_INJECT_SHELL]->()
        }
    """,
    "sandbox_escape": """
        coalesce(app.is_sandboxed, false) = false
        AND size(app.injection_methods) > 0
    """,
    "running_processes": """
        app.is_running = true
        AND size(app.injection_methods) > 0
    """,
    "icloud_risk": """
        EXISTS {
            MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement)
            WHERE app.bundle_id IS NOT NULL
        }
        AND size(app.injection_methods) > 0
    """,
    "blastpass_class": """
        size(app.injection_methods) > 0
    """,
    "firewall_exposure": """
        EXISTS {
            MATCH (app)-[:HAS_FIREWALL_RULE]->(:FirewallPolicy)
        }
        AND size(app.injection_methods) > 0
    """,
}

RISK_CATEGORY_PREDICATES: dict[str, str] = {
    "injectable_fda": SHARED_CATEGORY_PREDICATES["injectable_fda"],
    "dyld_injection": SHARED_CATEGORY_PREDICATES["dyld_injection"],
    "tcc_bypass": SHARED_CATEGORY_PREDICATES["tcc_bypass"],
    "electron_inheritance": """
        EXISTS {
            MATCH ()-[:CHILD_INHERITS_TCC]->(app)
        }
    """,
    "sip_bypass": SHARED_CATEGORY_PREDICATES["sip_bypass"],
    "persistence_hijack": SHARED_CATEGORY_PREDICATES["persistence_hijack"],
    "xpc_exploitation": SHARED_CATEGORY_PREDICATES["xpc_exploitation"],
    "apple_events": SHARED_CATEGORY_PREDICATES["apple_events"],
    "accessibility_abuse": SHARED_CATEGORY_PREDICATES["accessibility_abuse"],
    "kerberos": SHARED_CATEGORY_PREDICATES["kerberos"],
    "keychain_access": SHARED_CATEGORY_PREDICATES["keychain_access"],
    "kernel_escalation": SHARED_CATEGORY_PREDICATES["kernel_escalation"],
    "physical_security": """
        false
    """,
    "esf_bypass": """
        EXISTS {
            MATCH (app)-[:CAN_BLIND_MONITORING]->()
        }
    """,
    "shell_hooks": SHARED_CATEGORY_PREDICATES["shell_hooks"],
    "file_acl_escalation": """
        EXISTS {
            MATCH (app)-[:INSTALLED_ON]->(:Computer)<-[:LOCAL_TO]-(:User)-[:CAN_WRITE]->(:CriticalFile)
        }
    """,
    "sandbox_escape": SHARED_CATEGORY_PREDICATES["sandbox_escape"],
    "mdm_risk": """
        EXISTS {
            MATCH (:MDM_Profile)-[:CONFIGURES {bundle_id: app.bundle_id, allowed: true}]->(t:TCC_Permission)
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(t)
        }
    """,
    "running_processes": SHARED_CATEGORY_PREDICATES["running_processes"],
    "icloud_risk": SHARED_CATEGORY_PREDICATES["icloud_risk"],
    "firewall_exposure": SHARED_CATEGORY_PREDICATES["firewall_exposure"],
    "certificate_hygiene": SHARED_CATEGORY_PREDICATES["certificate_hygiene"],
    "blastpass_class": SHARED_CATEGORY_PREDICATES["blastpass_class"],
}

VULNERABILITY_CATEGORY_PREDICATES: dict[str, str] = {
    "injectable_fda": SHARED_CATEGORY_PREDICATES["injectable_fda"],
    "dyld_injection": SHARED_CATEGORY_PREDICATES["dyld_injection"],
    "tcc_bypass": SHARED_CATEGORY_PREDICATES["tcc_bypass"],
    "electron_inheritance": """
        EXISTS {
            MATCH (app)-[:CHILD_INHERITS_TCC]->()
        }
    """,
    "sip_bypass": SHARED_CATEGORY_PREDICATES["sip_bypass"],
    "persistence_hijack": SHARED_CATEGORY_PREDICATES["persistence_hijack"],
    "xpc_exploitation": SHARED_CATEGORY_PREDICATES["xpc_exploitation"],
    "apple_events": SHARED_CATEGORY_PREDICATES["apple_events"],
    "accessibility_abuse": SHARED_CATEGORY_PREDICATES["accessibility_abuse"],
    "kerberos": SHARED_CATEGORY_PREDICATES["kerberos"],
    "keychain_access": SHARED_CATEGORY_PREDICATES["keychain_access"],
    "kernel_escalation": SHARED_CATEGORY_PREDICATES["kernel_escalation"],
    "physical_security": """
        EXISTS {
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(:TCC_Permission)
        }
    """,
    "certificate_hygiene": SHARED_CATEGORY_PREDICATES["certificate_hygiene"],
    "shell_hooks": SHARED_CATEGORY_PREDICATES["shell_hooks"],
    "file_acl_escalation": """
        EXISTS {
            MATCH (app)-[:CAN_WRITE]->(:CriticalFile)
        }
    """,
    "esf_bypass": """
        EXISTS {
            MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement)
            WHERE app.name CONTAINS 'Security' OR app.name CONTAINS 'Endpoint'
        }
        AND size(app.injection_methods) > 0
    """,
    "sandbox_escape": SHARED_CATEGORY_PREDICATES["sandbox_escape"],
    "mdm_risk": """
        EXISTS {
            MATCH (app)-[:MDM_OVERGRANT]->()
        }
    """,
    "running_processes": SHARED_CATEGORY_PREDICATES["running_processes"],
    "icloud_risk": SHARED_CATEGORY_PREDICATES["icloud_risk"],
    "blastpass_class": SHARED_CATEGORY_PREDICATES["blastpass_class"],
    "firewall_exposure": SHARED_CATEGORY_PREDICATES["firewall_exposure"],
}

DIVERGENT_RISK_AND_VULNERABILITY_CATEGORIES = frozenset(
    {
        "electron_inheritance",
        "esf_bypass",
        "file_acl_escalation",
        "mdm_risk",
        "physical_security",
    }
)
