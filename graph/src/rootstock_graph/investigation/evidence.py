"""Stable evidence identities, provenance, coverage, and same-snapshot associations."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict

from ..models import ScanResult

# Identity deliberately excludes mutable facts, scan IDs and collection timestamps.
COLLECTIONS = {
    "applications": ("bundle_id", "path"),
    "launch_items": ("type", "path", "label"),
    "running_processes": ("pid",),
    "network_listeners": ("protocol", "address", "port", "pid"),
    "browser_extensions": ("browser", "profile", "extension_id"),
    "certificate_trust_settings": ("domain", "sha256"),
    "installed_packages": ("package_id",),
    "tcc_grants": ("service", "client", "client_type", "scope"),
    "file_acls": ("path",),
    "xpc_services": ("path", "label"),
    "remote_access_services": ("service",),
    "firewall_status": (),
    "system_extensions": ("identifier", "team_id", "extension_type"),
    "authorization_plugins": ("path", "name"),
    "authorization_rights": ("name",),
    "sudoers_rules": ("user", "host", "command"),
    "mdm_profiles": ("identifier",),
    "local_groups": ("name", "gid"),
}
SOURCE_NAMES = {
    "applications": ("entitlement", "appdiscovery", "codesigning"),
    "launch_items": ("persistence", "launchd", "launchctl"),
    "running_processes": ("processsnapshot",),
    "network_listeners": ("networklisteners",),
    "browser_extensions": ("browserextensions",),
    "certificate_trust_settings": ("trustsettings",),
    "installed_packages": ("installedpackages",),
    "tcc_grants": ("tcc",),
    "file_acls": ("fileacl",),
    "xpc_services": ("xpc",),
    "remote_access_services": ("remoteaccess", "ssh"),
    "firewall_status": ("firewall",),
    "system_extensions": ("systemextensions",),
    "authorization_plugins": ("authorization",),
    "authorization_rights": ("authorization",),
    "sudoers_rules": ("sudoers",),
    "mdm_profiles": ("mdm",),
    "local_groups": ("localgroups",),
}


def stable_id(kind: str, *parts: object) -> str:
    raw = json.dumps([kind, *parts], ensure_ascii=True, separators=(",", ":"))
    return kind + ":" + hashlib.sha256(raw.encode()).hexdigest()[:24]


def evidence_graph(scan: ScanResult) -> tuple[dict[str, dict], list[dict], list[dict]]:
    nodes: dict[str, dict] = {}
    coverage = []
    for collection, keys in COLLECTIONS.items():
        items = getattr(scan, collection)
        errors = [
            error.model_dump()
            for error in scan.errors
            if any(
                name in "".join(char for char in error.source.lower() if char.isalnum())
                for name in SOURCE_NAMES[collection]
            )
        ]
        status = "partial" if errors else "observed" if items else "unknown"
        coverage.append(
            {
                "collection": collection,
                "status": status,
                "count": len(items),
                "errors": errors,
                "reason": "Records present; completeness is not asserted"
                if items
                else "No records; the legacy scan does not attest successful collection of every source",
            }
        )
        for index, item in enumerate(items):
            facts = item.model_dump(mode="json")
            key = stable_id(collection, *(facts.get(field) for field in keys))
            if key in nodes:
                # Retain duplicate identities instead of silently replacing contradictory evidence.
                key = stable_id(collection, key, facts)
            nodes[key] = {
                "id": key,
                "kind": collection,
                "facts": facts,
                "source_pointer": f"/{collection}/{index}",
                "source": "normalized_scan",
                "scan_id": scan.scan_id,
            }
    host = stable_id("host", scan.hardware_uuid or scan.hostname)
    nodes[host] = {
        "id": host,
        "kind": "host",
        "source_pointer": "",
        "source": "normalized_scan",
        "scan_id": scan.scan_id,
        "facts": {
            key: getattr(scan, key)
            for key in (
                "hostname",
                "hardware_uuid",
                "macos_version",
                "sip_enabled",
                "gatekeeper_enabled",
                "filevault_enabled",
                "screen_lock_enabled",
            )
        }
        | {
            "network_configuration": scan.network_configuration.model_dump()
            if scan.network_configuration
            else None,
            "host_security_settings": scan.host_security_settings.model_dump()
            if scan.host_security_settings
            else None,
        },
    }
    return nodes, _relationships(nodes), coverage


def _relationships(nodes: dict[str, dict]) -> list[dict]:
    by_kind: dict[str, list[dict]] = defaultdict(list)
    for node in nodes.values():
        by_kind[node["kind"]].append(node)
    links: dict[tuple, dict] = {}

    def link(source: dict, target: dict, relation: str, basis: str) -> None:
        key = (source["id"], target["id"], relation)
        links[key] = {
            "source": source["id"],
            "target": target["id"],
            "relation": relation,
            "basis": basis,
            "classification": "association",
        }

    processes: dict[int, list[dict]] = defaultdict(list)
    for process in by_kind["running_processes"]:
        processes[process["facts"]["pid"]].append(process)
    for listener in by_kind["network_listeners"]:
        owners = processes.get(listener["facts"]["pid"], [])
        if len(owners) == 1:
            link(
                owners[0], listener, "listens_on", "PID in the same scan; collection is not atomic"
            )
    _process_links(by_kind, processes, link)
    return sorted(links.values(), key=lambda row: (row["source"], row["relation"], row["target"]))


def _index(nodes: list[dict], field: str) -> dict[object, list[dict]]:
    index: dict[object, list[dict]] = defaultdict(list)
    for node in nodes:
        if node["facts"].get(field) is not None:
            index[node["facts"][field]].append(node)
    return index


def _process_links(by_kind: dict, processes: dict, link) -> None:
    apps_by_path = _index(by_kind["applications"], "executable_path")
    jobs_by_path = _index(by_kind["launch_items"], "program")
    for process in by_kind["running_processes"]:
        facts = process["facts"]
        parents = processes.get(facts["ppid"], [])
        if len(parents) == 1 and parents[0]["id"] != process["id"]:
            link(
                parents[0],
                process,
                "parent_of",
                "Recorded PPID in the same scan; PID reuse is possible",
            )
        apps = apps_by_path.get(facts["command"], [])
        if len(apps) == 1:
            link(process, apps[0], "instance_of", "Exact recorded executable path")
        for launch in jobs_by_path.get(facts["command"], []):
            link(
                launch,
                process,
                "same_executable",
                "Exact path; does not prove this job started the process",
            )
