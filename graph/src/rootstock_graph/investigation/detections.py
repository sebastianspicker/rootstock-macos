"""Explainable review rules for observed configuration and inventory evidence."""

from __future__ import annotations

from .evidence import stable_id
from ..ingestion.launch_item_facts import DYLD_INJECTION_KEYS
from ..ingestion.import_nodes_inventory import broad_host_access, sensitive_permissions

RULESET_VERSION = "1"


def finding(
    rule: str,
    node: dict,
    priority: str,
    title: str,
    explanation: str,
    next_step: str,
    *,
    confidence: str = "observed",
    related: tuple[str, ...] = (),
) -> dict:
    return {
        "id": stable_id("finding", rule, node["id"]),
        "rule_id": rule,
        "priority": priority,
        "confidence": confidence,
        "title": title,
        "explanation": explanation,
        "next_step": next_step,
        "evidence_ids": [node["id"], *related],
        "disposition": "needs_review",
    }


def detect(nodes: dict[str, dict], links: list[dict]) -> list[dict]:
    handlers = {
        "launch_items": _persistence,
        "browser_extensions": _extension,
        "certificate_trust_settings": _certificate,
        "applications": _application,
        "file_acls": _permissions,
        "host": _host,
    }
    result = []
    for node in nodes.values():
        handler = handlers.get(node["kind"])
        if handler:
            result.extend(handler(node))
        elif node["kind"] == "network_listeners":
            result.extend(_listener(node, links))
    return result


def _listener(node: dict, links: list[dict]) -> list[dict]:
    facts = node["facts"]
    if facts["is_loopback"]:
        return []
    owners = tuple(
        link["source"]
        for link in links
        if link["target"] == node["id"] and link["relation"] == "listens_on"
    )
    return [
        finding(
            "network.non_loopback",
            node,
            "medium",
            "Non-loopback socket observed",
            f"{facts['protocol']} {facts['address']}:{facts['port']} is bound on a non-loopback address. "
            "This does not establish remote reachability or firewall policy.",
            "Confirm the owning service and whether this binding is intended; review local and upstream filtering.",
            related=owners,
        )
    ]


def _extension(node: dict) -> list[dict]:
    facts = node["facts"]
    sensitive = sensitive_permissions(facts["permissions"])
    broad = broad_host_access(facts["host_permissions"] + facts["permissions"])
    if facts["enabled"] is False or not sensitive or not broad:
        return []
    return [
        finding(
            "extension.broad_sensitive_access",
            node,
            "medium",
            "Extension has broad site access",
            "Broad host patterns combine with: "
            + ", ".join(sensitive)
            + ". "
            + (
                "Enabled state is unknown." if facts["enabled"] is None else "Extension is enabled."
            ),
            "Verify the publisher, installation source and business need before changing permissions.",
        )
    ]


def _certificate(node: dict) -> list[dict]:
    if node["facts"]["trust_result"] not in {"trust_root", "trust_as_root"}:
        return []
    return [
        finding(
            "trust.custom_root",
            node,
            "low",
            "Custom certificate trust requires attribution",
            "A user or administrator trust setting is recorded. Managed roots may be expected.",
            "Compare the certificate fingerprint and trust policy with approved MDM or proxy configuration.",
        )
    ]


def _application(node: dict) -> list[dict]:
    facts = node["facts"]
    if facts["signed"] is not False or facts["code_signing_analysis_error"]:
        return []
    return [
        finding(
            "application.unsigned",
            node,
            "medium",
            "Unsigned application observed",
            "The collector reports no valid code signature; this alone is not evidence of malware.",
            "Verify its source, executable hash and expected signing identity with the software owner.",
        )
    ]


def _permissions(node: dict) -> list[dict]:
    if not node["facts"]["is_writable_by_non_root"]:
        return []
    return [
        finding(
            "permissions.sensitive_writable",
            node,
            "high",
            "Sensitive configuration is writable by a non-root account",
            f"Recorded permissions allow non-root writes to {node['facts']['category']} metadata.",
            "Review the recorded owner, mode and ACL against the expected policy before correcting access.",
        )
    ]


def _host(node: dict) -> list[dict]:
    return [
        finding(
            "posture." + field,
            node,
            "high",
            field.replace("_enabled", "").replace("_", " ").title() + " is disabled",
            "The collector explicitly recorded this protection as disabled.",
            "Confirm whether an approved exception exists and restore the protection when appropriate.",
        )
        for field in (
            "sip_enabled",
            "gatekeeper_enabled",
            "filevault_enabled",
            "screen_lock_enabled",
        )
        if node["facts"][field] is False
    ]


def _persistence(node: dict) -> list[dict]:
    facts = node["facts"]
    result = []
    active = facts["loaded"] is True
    root_job = facts["type"] == "daemon" and facts["user"] in (None, "root")
    if facts["program_writable_by_non_root"] or facts["plist_writable_by_non_root"]:
        result.append(
            finding(
                "persistence.writable",
                node,
                "high" if root_job else "medium",
                "Persistence configuration or program is writable",
                "Recorded file permissions permit non-root changes. "
                + (
                    "This is a system daemon with root or default execution identity."
                    if root_job
                    else "Review the job's execution identity."
                ),
                "Verify ownership, ACLs and the approved installation source before repairing permissions.",
            )
        )
    variables = sorted(DYLD_INJECTION_KEYS & facts["dyld_environment"].keys())
    if variables:
        result.append(
            finding(
                "persistence.loader_environment",
                node,
                "medium",
                "Launch item customizes library loading",
                "Recorded variables: "
                + ", ".join(variables)
                + ". Their presence does not prove they were honored or malicious.",
                "Compare the plist and referenced library paths with the vendor's expected configuration.",
            )
        )
    if facts["program_exists"] is False:
        result.append(
            finding(
                "persistence.missing_program",
                node,
                "medium" if active else "low",
                "Launch item references a missing program",
                "The program was absent during collection. Loaded state: "
                + str(facts["loaded"])
                + ".",
                "Check for an incomplete upgrade or uninstall, and preserve the plist before any cleanup.",
            )
        )
    return result
