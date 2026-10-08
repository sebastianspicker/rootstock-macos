"""import_nodes_network.py - Runtime evidence: processes, network listeners, host settings.

Every node created here carries the scan's ``scan_id`` (and its key starts with it),
so ``replace_host`` removes it together with the rest of an earlier scan.

  (:Process)-[:INSTANCE_OF]->(:Application)        same scan, same bundle id
  (:Process)-[:PARENT_OF]->(:Process)              from ``ppid``
  (:Process)-[:RUNS_ON]->(:Computer)
  (:Process)-[:LISTENS_ON]->(:NetworkListener)     same pid
  (:Application)-[:LISTENS_ON]->(:NetworkListener) same scan, same bundle id
  (:NetworkListener)-[:EXPOSED_ON]->(:Computer)

Host security settings and network configuration become properties of the
scan's Computer node (Neo4j properties cannot be maps, so nested values are
flattened into scalar properties or lists of strings).
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from neo4j import Session

from ..models import (
    LaunchItemData,
    RunningProcessData,
)
from ..models_inventory import (
    HostSecuritySettingsData,
    NetworkConfigurationData,
    NetworkListenerData,
    ProxySettingData,
)
from .path_classification import command_in_user_writable_location
from .launch_item_facts import dyld_injection

__all__ = [
    "host_settings_properties",
    "import_host_settings",
    "import_network_listeners",
    "import_processes",
    "launch_item_summary_properties",
    "listener_key",
    "network_configuration_properties",
    "process_key",
    "reachable_without_firewall",
]

_SOFTWARE_UPDATE_FIELDS = (
    "automatic_check",
    "automatic_download",
    "install_security_responses",
    "install_system_updates",
    "install_app_updates",
    "last_successful_check",
)
_HOST_SETTING_FIELDS = (
    "guest_account_enabled",
    "auto_login_user",
    "root_account_enabled",
    "remote_apple_events_enabled",
    "remote_management_enabled",
    "xprotect_version",
    "xprotect_remediator_version",
    "mrt_version",
)


def _computer_key(scan_id: str, hostname: str) -> str:
    return f"{scan_id}:{hostname}"


# ── Processes ────────────────────────────────────────────────────────────────


def process_key(scan_id: str, pid: int) -> str:
    """Process identity: pids are only unique within one scan."""
    return f"{scan_id}:{pid}"


def _process_records(processes: list[RunningProcessData], scan_id: str) -> list[dict]:
    records: dict[int, dict] = {}
    for process in processes:
        records[process.pid] = {
            "process_key": process_key(scan_id, process.pid),
            "parent_key": process_key(scan_id, process.ppid) if process.ppid is not None else None,
            "pid": process.pid,
            "ppid": process.ppid,
            "user": process.user,
            "command": process.command,
            "bundle_id": process.bundle_id,
            "command_in_user_writable_location": command_in_user_writable_location(process.command),
        }
    return [records[pid] for pid in sorted(records)]


def import_processes(
    session: Session, processes: list[RunningProcessData], hostname: str, scan_id: str
) -> tuple[int, int, int, int]:
    """MERGE Process nodes and their edges. Returns (nodes, INSTANCE_OF, PARENT_OF, RUNS_ON)."""
    if not processes:
        return 0, 0, 0, 0
    records = _process_records(processes, scan_id)
    session.run(
        """
        UNWIND $records AS r
        MERGE (p:Process {process_key: r.process_key})
        SET p.pid = r.pid,
            p.ppid = r.ppid,
            p.user = r.user,
            p.command = r.command,
            p.bundle_id = r.bundle_id,
            p.command_in_user_writable_location = r.command_in_user_writable_location,
            p.scan_id = $scan_id
        """,
        records=records,
        scan_id=scan_id,
    )
    instance_of = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE r.bundle_id IS NOT NULL
        MATCH (p:Process {process_key: r.process_key})
        MATCH (a:Application {scan_id: $scan_id, bundle_id: r.bundle_id})
        MERGE (p)-[rel:INSTANCE_OF]->(a)
        RETURN count(rel) AS n
        """,
        records=records,
        scan_id=scan_id,
    ).single()["n"]
    parent_of = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE r.parent_key IS NOT NULL AND r.parent_key <> r.process_key
        MATCH (child:Process {process_key: r.process_key})
        MATCH (parent:Process {process_key: r.parent_key})
        MERGE (parent)-[rel:PARENT_OF]->(child)
        RETURN count(rel) AS n
        """,
        records=records,
    ).single()["n"]
    runs_on = session.run(
        """
        MATCH (c:Computer {computer_key: $computer_key})
        MATCH (p:Process {scan_id: $scan_id})
        MERGE (p)-[rel:RUNS_ON]->(c)
        RETURN count(rel) AS n
        """,
        computer_key=_computer_key(scan_id, hostname),
        scan_id=scan_id,
    ).single()["n"]
    return len(records), instance_of, parent_of, runs_on


# ── Network listeners ────────────────────────────────────────────────────────


def listener_key(scan_id: str, listener: NetworkListenerData) -> str:
    pid = listener.pid if listener.pid is not None else "-"
    return f"{scan_id}:{listener.protocol}:{listener.address}:{listener.port}:{pid}"


def reachable_without_firewall(exposed: bool, firewall_enabled: bool | None) -> bool | None:
    """An exposed listener is reachable unfiltered when the firewall is off; unknown stays None."""
    if not exposed:
        return False
    if firewall_enabled is None:
        return None
    return firewall_enabled is False


def _listener_records(
    listeners: list[NetworkListenerData], scan_id: str, firewall_enabled: bool | None
) -> list[dict]:
    records: dict[str, dict] = {}
    for listener in listeners:
        key = listener_key(scan_id, listener)
        exposed = not listener.is_loopback
        records[key] = {
            "listener_key": key,
            "process_key": process_key(scan_id, listener.pid) if listener.pid is not None else None,
            "endpoint": f"{listener.protocol} {listener.address}:{listener.port}",
            "protocol": listener.protocol,
            "address": listener.address,
            "port": listener.port,
            "is_loopback": listener.is_loopback,
            "state": listener.state,
            "pid": listener.pid,
            "process_name": listener.process_name,
            "user": listener.user,
            "bundle_id": listener.bundle_id,
            "exposed": exposed,
            "firewall_enabled": firewall_enabled,
            "reachable_without_firewall": reachable_without_firewall(exposed, firewall_enabled),
        }
    return [records[key] for key in sorted(records)]


def import_network_listeners(
    session: Session,
    listeners: list[NetworkListenerData],
    hostname: str,
    scan_id: str,
    firewall_enabled: bool | None = None,
) -> tuple[int, int, int]:
    """MERGE NetworkListener nodes. Returns (nodes, LISTENS_ON, EXPOSED_ON)."""
    if not listeners:
        return 0, 0, 0
    records = _listener_records(listeners, scan_id, firewall_enabled)
    session.run(
        """
        UNWIND $records AS r
        MERGE (nl:NetworkListener {listener_key: r.listener_key})
        SET nl.endpoint = r.endpoint,
            nl.protocol = r.protocol,
            nl.address = r.address,
            nl.port = r.port,
            nl.is_loopback = r.is_loopback,
            nl.state = r.state,
            nl.pid = r.pid,
            nl.process_name = r.process_name,
            nl.user = r.user,
            nl.bundle_id = r.bundle_id,
            nl.exposed = r.exposed,
            nl.firewall_enabled = r.firewall_enabled,
            nl.reachable_without_firewall = r.reachable_without_firewall,
            nl.scan_id = $scan_id
        """,
        records=records,
        scan_id=scan_id,
    )
    listens_on = session.run(
        """
        UNWIND $records AS r
        MATCH (nl:NetworkListener {listener_key: r.listener_key})
        OPTIONAL MATCH (p:Process {process_key: r.process_key})
        OPTIONAL MATCH (a:Application {scan_id: $scan_id, bundle_id: r.bundle_id})
        WITH nl, [x IN collect(DISTINCT p) + collect(DISTINCT a) WHERE x IS NOT NULL] AS owners
        UNWIND owners AS owner
        MERGE (owner)-[rel:LISTENS_ON]->(nl)
        RETURN count(rel) AS n
        """,
        records=records,
        scan_id=scan_id,
    ).single()["n"]
    exposed_on = session.run(
        """
        MATCH (c:Computer {computer_key: $computer_key})
        MATCH (nl:NetworkListener {scan_id: $scan_id})
        MERGE (nl)-[rel:EXPOSED_ON]->(c)
        RETURN count(rel) AS n
        """,
        computer_key=_computer_key(scan_id, hostname),
        scan_id=scan_id,
    ).single()["n"]
    return len(records), listens_on, exposed_on


# ── Host settings on the Computer node ──────────────────────────────────────


def host_settings_properties(settings: HostSecuritySettingsData | None) -> dict[str, object]:
    """Flatten host_security_settings (``software_update.*`` → ``software_update_<key>``)."""
    props: dict[str, object] = {
        field: getattr(settings, field) if settings else None for field in _HOST_SETTING_FIELDS
    }
    update = settings.software_update if settings else None
    for field in _SOFTWARE_UPDATE_FIELDS:
        props[f"software_update_{field}"] = getattr(update, field) if update else None
    return props


def sanitized_proxy_url(url: str | None) -> str:
    """URL with userinfo, query and fragment removed (scheme, host, port and path kept).

    The collector already strips these from PAC URLs; older scans may still carry them.
    Unparseable URLs become an empty string rather than being stored verbatim.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return ""
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _proxy_string(proxy: ProxySettingData) -> str:
    if proxy.kind == "pac" or proxy.host is None:
        target = sanitized_proxy_url(proxy.url)
    elif proxy.port is not None:
        target = f"{proxy.host}:{proxy.port}"
    else:
        target = proxy.host
    return f"{proxy.service} {proxy.kind} {target}".rstrip()


def network_configuration_properties(config: NetworkConfigurationData | None) -> dict[str, object]:
    """DNS, search domains, proxies and hosts entries as list-of-string properties."""
    if config is None:
        return {
            "dns_servers": None,
            "search_domains": None,
            "proxy_settings": None,
            "hosts_entries": None,
            "proxy_count": None,
            "hosts_entry_count": None,
        }
    return {
        "dns_servers": list(config.dns_servers),
        "search_domains": list(config.search_domains),
        "proxy_settings": [_proxy_string(proxy) for proxy in config.proxies],
        "hosts_entries": [
            " ".join([entry.address, *entry.hostnames]) for entry in config.hosts_entries
        ],
        "proxy_count": len(config.proxies),
        "hosts_entry_count": len(config.hosts_entries),
    }


def launch_item_summary_properties(items: list[LaunchItemData]) -> dict[str, object]:
    """Per-scan launch item counts (LaunchItem nodes themselves are shared across scans)."""
    return {
        "stale_launch_item_count": sum(1 for item in items if item.program_exists is False),
        "launchd_env_injection_count": sum(
            1 for item in items if dyld_injection(item.dyld_environment)
        ),
    }


def import_host_settings(session: Session, scan) -> int:
    """Write host settings and network configuration onto this scan's Computer node."""
    props = {
        **host_settings_properties(scan.host_security_settings),
        **network_configuration_properties(scan.network_configuration),
        **launch_item_summary_properties(scan.launch_items),
    }
    result = session.run(
        """
        MATCH (c:Computer {computer_key: $computer_key})
        SET c += $props
        RETURN count(c) AS n
        """,
        computer_key=_computer_key(scan.scan_id, scan.hostname),
        props=props,
    )
    return result.single()["n"]
