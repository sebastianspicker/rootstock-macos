"""Compare durable observed evidence, never treating absence as remediation."""

from __future__ import annotations

from datetime import datetime

from ..models import ScanResult

# PID and socket ownership are point-in-time facts, unsuitable for stable baselines.
DURABLE_KINDS = {
    "applications",
    "launch_items",
    "browser_extensions",
    "certificate_trust_settings",
    "installed_packages",
    "tcc_grants",
    "file_acls",
    "host",
    "xpc_services",
    "remote_access_services",
    "firewall_status",
    "system_extensions",
    "authorization_plugins",
    "authorization_rights",
    "sudoers_rules",
    "mdm_profiles",
    "local_groups",
}


def validate_baseline(before: ScanResult, after: ScanResult) -> list[str]:
    warnings = []
    if before.hardware_uuid and after.hardware_uuid:
        if before.hardware_uuid.lower() != after.hardware_uuid.lower():
            raise ValueError("Baseline hardware UUID differs from the current scan")
    elif before.hostname != after.hostname:
        raise ValueError(
            "Cannot establish the same host: hardware UUID unavailable and hostnames differ"
        )
    else:
        warnings.append(
            "Baseline host identity relies on hostname because a hardware UUID is missing"
        )
    try:
        old, new = (
            datetime.fromisoformat(scan.timestamp.replace("Z", "+00:00"))
            for scan in (before, after)
        )
        if old.tzinfo is None or new.tzinfo is None:
            raise ValueError("timestamps require timezones")
        if old > new:
            raise ValueError("Baseline timestamp is later than the current scan")
    except (TypeError, ValueError) as error:
        raise ValueError(f"Cannot compare baseline timestamps: {error}") from error
    return warnings


def compare_evidence(before: dict[str, dict], after: dict[str, dict]) -> dict:
    old = {key: value for key, value in before.items() if value["kind"] in DURABLE_KINDS}
    new = {key: value for key, value in after.items() if value["kind"] in DURABLE_KINDS}
    changed = []
    for key in sorted(old.keys() & new.keys()):
        fields = {
            field: {"before": old[key]["facts"].get(field), "after": value}
            for field, value in new[key]["facts"].items()
            if old[key]["facts"].get(field) != value
        }
        if fields:
            changed.append({"evidence_id": key, "kind": new[key]["kind"], "fields": fields})
    return {
        "added": [new[key] for key in sorted(new.keys() - old.keys())],
        "no_longer_observed": [old[key] for key in sorted(old.keys() - new.keys())],
        "changed": changed,
        "limitations": [
            "Missing records do not prove removal, remediation or successful collection",
            "Processes and sockets are excluded from durable comparison because PIDs can be reused",
            "CVE findings use the current local cache; historical CVE state is not reconstructed",
        ],
    }


def change_findings(comparison: dict, nodes: dict[str, dict]) -> list[dict]:
    from .detections import finding

    findings = []
    for change in comparison["changed"]:
        node = nodes[change["evidence_id"]]
        fields = change["fields"]
        for field in ("executable_sha256", "program_sha256", "team_id", "program_team_id"):
            delta = fields.get(field)
            if delta and delta["before"] and delta["after"]:
                findings.append(
                    finding(
                        "change." + field,
                        node,
                        "medium",
                        "Executable or signing identity changed",
                        f"{field} differs from the baseline. This can be expected after a software update.",
                        "Compare the before/after values in baseline changes with the approved update or installation record.",
                    )
                    | {"baseline_status": "changed", "baseline_evidence": {field: delta}}
                )
        if node["kind"] == "browser_extensions":
            for field in ("permissions", "host_permissions"):
                delta = fields.get(field)
                if delta and set(delta["after"]) - set(delta["before"]):
                    findings.append(
                        finding(
                            "change.extension_" + field,
                            node,
                            "medium",
                            "Browser extension permissions expanded",
                            "Newly declared permissions: "
                            + ", ".join(sorted(set(delta["after"]) - set(delta["before"]))),
                            "Confirm the extension update and review why the additional permissions are needed.",
                        )
                        | {"baseline_status": "changed", "baseline_evidence": {field: delta}}
                    )
    return findings
