"""Shared Application category predicates for risk and vulnerability workflows.

Two consumers read these Cypher fragments (each fragment assumes a bound ``app``):

* ``RISK_CATEGORY_PREDICATES`` decide the ``attack_categories`` written on every
  Application node, which drive the finding counts and the per-app risk story. A
  category must therefore describe something *specific to that app* that an
  operator can act on. Host-wide facts (a keytab exists somewhere, a user can
  write their own shell profile) are deliberately not app categories.
* ``VULNERABILITY_CATEGORY_PREDICATES`` select the apps that receive
  ``HAS_CVE_CONTEXT`` edges to the reference CVEs of a technique class. Those
  edges are context, never evidence that the app is affected, so broader
  heuristics (``tcc_bypass``, ``blastpass_class``) are acceptable there.
"""

from __future__ import annotations

_PRIVILEGED_CRITICAL_FILE_CATEGORIES = (
    "'tcc_database', 'sudoers', 'launch_daemon_dir', 'authorization_db', 'ssh_config'"
)

# A browser extension worth reviewing: broad host access together with a permission
# that reads or rewrites traffic/sessions, or installed outside the store
# (unpacked developer load, or side-loaded by another program).
RISKY_BROWSER_EXTENSION = (
    "((be.broad_host_access = true AND size(coalesce(be.sensitive_permissions, [])) > 0)"
    " OR be.install_location IN ['unpacked', 'external'])"
)

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
    # Only `com.apple.rootless.*` entitlements let a process touch SIP-protected
    # locations; any other entitlement on a third-party app says nothing about SIP.
    "sip_bypass": """
        EXISTS {
            MATCH (app)-[:HAS_ENTITLEMENT]->(e:Entitlement)
            WHERE e.name STARTS WITH 'com.apple.rootless.'
        }
        AND size(app.injection_methods) > 0
    """,
    # A program under /tmp, /Users/Shared or a user's home (outside ~/Applications)
    # can be swapped by that user as easily as a writable one.
    "persistence_hijack": """
        EXISTS {
            MATCH (app)-[:PERSISTS_VIA]->(li:LaunchItem)
            WHERE li.program_writable_by_non_root = true OR li.plist_writable_by_non_root = true
               OR li.program_in_user_writable_location = true
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
    # The app itself must be able to reach a Kerberos artifact (inferred by
    # infer_kerberos); a keytab or ticket cache merely existing on the host is not
    # an attribute of every installed app.
    "kerberos": """
        EXISTS {
            MATCH (app)-[:CAN_READ_KERBEROS]->(:KerberosArtifact)
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
    # CAN_INJECT_SHELL runs from a User to a CriticalFile, so an app is exposed when
    # it persists as that user: code injected into the app survives in the shell
    # profile the same account owns.
    "shell_hooks": """
        EXISTS {
            MATCH (app)-[:PERSISTS_VIA]->(:LaunchItem)-[:RUNS_AS]->(:User)-[:CAN_INJECT_SHELL]->(:CriticalFile)
        }
    """,
    # A sandbox can only be escaped by a sandboxed app; infer_sandbox records the
    # modeled escape vector as CAN_ESCAPE_SANDBOX.
    "sandbox_escape": """
        EXISTS {
            MATCH ()-[:CAN_ESCAPE_SANDBOX]->(app)
        }
    """,
    "running_processes": """
        app.is_running = true
        AND size(app.injection_methods) > 0
    """,
    "icloud_risk": """
        EXISTS {
            MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement {category: 'icloud'})
        }
        AND size(app.injection_methods) > 0
    """,
    "blastpass_class": """
        size(app.injection_methods) > 0
    """,
    # Exposure needs an incoming-allow rule; a block rule or an unknown state is not
    # exposure.
    "firewall_exposure": """
        EXISTS {
            MATCH (app)-[:HAS_FIREWALL_RULE {allow_incoming: true}]->(:FirewallPolicy)
        }
        AND size(app.injection_methods) > 0
    """,
}


def _category_predicates(
    overrides: dict[str, str],
    *,
    exclude: frozenset[str] = frozenset(),
) -> dict[str, str]:
    merged = {**SHARED_CATEGORY_PREDICATES, **overrides}
    return {key: value for key, value in merged.items() if key not in exclude}


# Categories that are useful CVE context but say nothing app-specific: every app
# with a grant would be "tcc_bypass" and every injectable app "blastpass_class".
_CONTEXT_ONLY_CATEGORIES = frozenset({"tcc_bypass", "blastpass_class"})

RISK_CATEGORY_PREDICATES: dict[str, str] = _category_predicates(
    {
        "electron_inheritance": """
        EXISTS {
            MATCH ()-[:CHILD_INHERITS_TCC]->(app)
        }
    """,
        "physical_security": """
        false
    """,
        "esf_bypass": """
        EXISTS {
            MATCH (app)-[:CAN_BLIND_MONITORING]->()
        }
    """,
        "shell_hooks": SHARED_CATEGORY_PREDICATES["shell_hooks"],
        # Only files whose write access would escalate privilege count: a user who
        # can write their own login keychain or shell profile has no new capability,
        # a user who can write sudoers, a LaunchDaemon, or the system TCC store does.
        "file_acl_escalation": f"""
        EXISTS {{
            MATCH (app)-[:INSTALLED_ON]->(:Computer)<-[:LOCAL_TO]-(:User)-[:CAN_WRITE]->(cf:CriticalFile)
            WHERE cf.category IN [{_PRIVILEGED_CRITICAL_FILE_CATEGORIES}]
               OR cf.is_world_writable = true
               OR cf.is_group_writable = true
        }}
    """,
        "sandbox_escape": SHARED_CATEGORY_PREDICATES["sandbox_escape"],
        "mdm_risk": """
        EXISTS {
            MATCH (:MDM_Profile)-[:CONFIGURES {bundle_id: app.bundle_id, allowed: true}]->(t:TCC_Permission)
            MATCH (app)-[:HAS_TCC_GRANT {allowed: true}]->(t)
        }
    """,
        # launchd sets DYLD_* for the job, loading a library into the app's helper at
        # every start: injection that survives updates and needs no exploit.
        "launchd_env_injection": """
        EXISTS {
            MATCH (app)-[:PERSISTS_VIA]->(li:LaunchItem)
            WHERE li.launchd_dyld_injection = true
        }
    """,
        # Informational: the job points at a program that no longer exists.
        "stale_persistence": """
        EXISTS {
            MATCH (app)-[:PERSISTS_VIA]->(li:LaunchItem)
            WHERE li.program_exists = false
        }
    """,
        "network_exposed": """
        EXISTS {
            MATCH (app)-[:LISTENS_ON]->(nl:NetworkListener)
            WHERE nl.exposed = true
        }
    """,
        "browser_extension_risk": f"""
        EXISTS {{
            MATCH (app)-[:HAS_EXTENSION]->(be:BrowserExtension)
            WHERE {RISKY_BROWSER_EXTENSION}
        }}
    """,
    },
    exclude=_CONTEXT_ONLY_CATEGORIES,
)

VULNERABILITY_CATEGORY_PREDICATES: dict[str, str] = _category_predicates(
    {
        "electron_inheritance": """
        EXISTS {
            MATCH ()-[:CHILD_INHERITS_TCC]->(app)
        }
    """,
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
            MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement {name: 'com.apple.developer.endpoint-security.client'})
        }
        AND size(app.injection_methods) > 0
    """,
        "gatekeeper_bypass": """
        EXISTS {
            MATCH ()-[:BYPASSED_GATEKEEPER]->(app)
        }
    """,
        "sandbox_escape": SHARED_CATEGORY_PREDICATES["sandbox_escape"],
        "mdm_risk": """
        EXISTS {
            MATCH (app)-[:MDM_OVERGRANT]->()
        }
    """,
    }
)

DIVERGENT_RISK_AND_VULNERABILITY_CATEGORIES = frozenset(
    {
        "electron_inheritance",
        "esf_bypass",
        "file_acl_escalation",
        "mdm_risk",
        "physical_security",
    }
)
