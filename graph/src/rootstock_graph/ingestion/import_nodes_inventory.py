"""import_nodes_inventory.py - Host inventory: trusted certificates, browser extensions, packages.

Every node created here carries the scan's ``scan_id`` (and its key starts with it),
so ``replace_host`` removes it together with the rest of an earlier scan.

  (:Computer)-[:TRUSTS_CERTIFICATE]->(:TrustedCertificate)
  (:TrustedCertificate)-[:SAME_CERTIFICATE]->(:CertificateAuthority)   same SHA-256
  (:Application)-[:HAS_EXTENSION]->(:BrowserExtension)                 browser app, same scan
  (:BrowserExtension)-[:INSTALLED_ON]->(:Computer)                     no browser app node
  (:InstalledPackage)-[:INSTALLED_ON]->(:Computer)
  (:Application)-[:INSTALLED_BY]->(:InstalledPackage)                  package id ~ bundle id
"""

from __future__ import annotations

from neo4j import Session

from ..models import (
    ApplicationData,
)
from ..models_inventory import (
    BrowserExtensionData,
    InstalledPackageData,
    TrustedCertificateData,
)

__all__ = [
    "BROAD_HOST_PATTERNS",
    "SENSITIVE_EXTENSION_PERMISSIONS",
    "broad_host_access",
    "certificate_key",
    "extension_key",
    "import_browser_extensions",
    "import_installed_packages",
    "import_trusted_certificates",
    "package_key",
    "package_matches_bundle",
    "sensitive_permissions",
]

# Match patterns that let an extension read and change every page (or local files).
BROAD_HOST_PATTERNS = frozenset({"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "file:///*"})

# Permissions that let an extension observe or alter traffic, sessions, history,
# other extensions, or reach native code.
SENSITIVE_EXTENSION_PERMISSIONS = frozenset(
    {
        "webRequest",
        "webRequestBlocking",
        "declarativeNetRequest",
        "cookies",
        "history",
        "tabs",
        "clipboardRead",
        "nativeMessaging",
        "debugger",
        "proxy",
        "management",
        "downloads",
        "privacy",
        "scripting",
        "webNavigation",
    }
)

_CUSTOM_ROOT_RESULTS = frozenset({"trust_root", "trust_as_root"})


def _computer_key(scan_id: str, hostname: str) -> str:
    return f"{scan_id}:{hostname}"


# ── Trusted certificates ────────────────────────────────────────────────────


def certificate_key(scan_id: str, domain: str, sha256: str) -> str:
    return f"{scan_id}:{domain}:{sha256}"


def _certificate_records(certificates: list[TrustedCertificateData], scan_id: str) -> list[dict]:
    records: dict[str, dict] = {}
    for cert in certificates:
        key = certificate_key(scan_id, cert.domain, cert.sha256.lower())
        records[key] = {
            "certificate_key": key,
            "sha256": cert.sha256.lower(),
            "subject": cert.subject,
            "issuer": cert.issuer,
            "domain": cert.domain,
            "trust_result": cert.trust_result,
            "is_self_signed": cert.is_self_signed,
            "not_after": cert.not_after,
            "custom_root": cert.trust_result in _CUSTOM_ROOT_RESULTS,
        }
    return [records[key] for key in sorted(records)]


def import_trusted_certificates(
    session: Session, certificates: list[TrustedCertificateData], hostname: str, scan_id: str
) -> tuple[int, int, int]:
    """MERGE TrustedCertificate nodes. Returns (nodes, TRUSTS_CERTIFICATE, SAME_CERTIFICATE)."""
    if not certificates:
        return 0, 0, 0
    records = _certificate_records(certificates, scan_id)
    trusts = session.run(
        """
        UNWIND $records AS r
        MERGE (tc:TrustedCertificate {certificate_key: r.certificate_key})
        SET tc.sha256 = r.sha256,
            tc.subject = r.subject,
            tc.issuer = r.issuer,
            tc.domain = r.domain,
            tc.trust_result = r.trust_result,
            tc.is_self_signed = r.is_self_signed,
            tc.not_after = r.not_after,
            tc.custom_root = r.custom_root,
            tc.scan_id = $scan_id
        WITH tc
        MATCH (c:Computer {computer_key: $computer_key})
        MERGE (c)-[rel:TRUSTS_CERTIFICATE]->(tc)
        RETURN count(rel) AS n
        """,
        records=records,
        scan_id=scan_id,
        computer_key=_computer_key(scan_id, hostname),
    ).single()["n"]
    same = session.run(
        """
        MATCH (tc:TrustedCertificate {scan_id: $scan_id})
        MATCH (ca:CertificateAuthority)
        WHERE toLower(ca.sha256) = tc.sha256
        MERGE (tc)-[rel:SAME_CERTIFICATE]->(ca)
        RETURN count(rel) AS n
        """,
        scan_id=scan_id,
    ).single()["n"]
    return len(records), trusts, same


# ── Browser extensions ──────────────────────────────────────────────────────


def extension_key(scan_id: str, extension: BrowserExtensionData) -> str:
    return f"{scan_id}:{extension.browser}:{extension.profile}:{extension.extension_id}"


def broad_host_access(host_permissions: list[str]) -> bool:
    return any(pattern in BROAD_HOST_PATTERNS for pattern in host_permissions)


def sensitive_permissions(permissions: list[str]) -> list[str]:
    return sorted(set(permissions) & SENSITIVE_EXTENSION_PERMISSIONS)


def _extension_records(extensions: list[BrowserExtensionData], scan_id: str) -> list[dict]:
    records: dict[str, dict] = {}
    for ext in extensions:
        key = extension_key(scan_id, ext)
        records[key] = {
            "extension_key": key,
            **ext.model_dump(),
            "broad_host_access": broad_host_access(ext.host_permissions),
            "sensitive_permissions": sensitive_permissions(ext.permissions),
        }
    return [records[key] for key in sorted(records)]


def import_browser_extensions(
    session: Session, extensions: list[BrowserExtensionData], hostname: str, scan_id: str
) -> tuple[int, int, int]:
    """MERGE BrowserExtension nodes. Returns (nodes, HAS_EXTENSION, INSTALLED_ON)."""
    if not extensions:
        return 0, 0, 0
    records = _extension_records(extensions, scan_id)
    session.run(
        """
        UNWIND $records AS r
        MERGE (be:BrowserExtension {extension_key: r.extension_key})
        SET be.browser = r.browser,
            be.browser_bundle_id = r.browser_bundle_id,
            be.profile = r.profile,
            be.extension_id = r.extension_id,
            be.name = r.name,
            be.version = r.version,
            be.manifest_version = r.manifest_version,
            be.permissions = r.permissions,
            be.host_permissions = r.host_permissions,
            be.from_webstore = r.from_webstore,
            be.enabled = r.enabled,
            be.install_time = r.install_time,
            be.install_location = r.install_location,
            be.path = r.path,
            be.broad_host_access = r.broad_host_access,
            be.sensitive_permissions = r.sensitive_permissions,
            be.scan_id = $scan_id
        """,
        records=records,
        scan_id=scan_id,
    )
    has_extension = session.run(
        """
        UNWIND $records AS r
        WITH r WHERE r.browser_bundle_id IS NOT NULL
        MATCH (be:BrowserExtension {extension_key: r.extension_key})
        MATCH (a:Application {scan_id: $scan_id, bundle_id: r.browser_bundle_id})
        MERGE (a)-[rel:HAS_EXTENSION]->(be)
        RETURN count(rel) AS n
        """,
        records=records,
        scan_id=scan_id,
    ).single()["n"]
    installed_on = session.run(
        """
        MATCH (c:Computer {computer_key: $computer_key})
        MATCH (be:BrowserExtension {scan_id: $scan_id})
        WHERE NOT EXISTS { MATCH (:Application)-[:HAS_EXTENSION]->(be) }
        MERGE (be)-[rel:INSTALLED_ON]->(c)
        RETURN count(rel) AS n
        """,
        computer_key=_computer_key(scan_id, hostname),
        scan_id=scan_id,
    ).single()["n"]
    return len(records), has_extension, installed_on


# ── Installed packages ──────────────────────────────────────────────────────


def package_key(scan_id: str, package_id: str) -> str:
    return f"{scan_id}:{package_id}"


def _vendor_prefix(identifier: str) -> str | None:
    labels = identifier.split(".")
    return ".".join(labels[:3]) if len(labels) >= 3 else None


def package_matches_bundle(package_id: str, bundle_id: str) -> bool:
    """A receipt belongs to an app when the ids agree or share a three-label vendor prefix."""
    package, bundle = package_id.lower(), bundle_id.lower()
    if package == bundle or package.startswith(bundle + "."):
        return True
    vendor = _vendor_prefix(package)
    return vendor is not None and vendor == _vendor_prefix(bundle)


def _package_records(packages: list[InstalledPackageData], scan_id: str) -> list[dict]:
    records = {
        package.package_id: {"package_key": package_key(scan_id, package.package_id)}
        | package.model_dump()
        for package in packages
    }
    return [records[package_id] for package_id in sorted(records)]


def _installed_by_pairs(
    packages: list[dict], applications: list[ApplicationData]
) -> list[dict[str, str]]:
    bundle_ids = sorted({app.bundle_id for app in applications})
    return [
        {"bundle_id": bundle_id, "package_key": package["package_key"]}
        for package in packages
        for bundle_id in bundle_ids
        if package_matches_bundle(package["package_id"], bundle_id)
    ]


def import_installed_packages(
    session: Session,
    packages: list[InstalledPackageData],
    applications: list[ApplicationData],
    hostname: str,
    scan_id: str,
) -> tuple[int, int, int]:
    """MERGE InstalledPackage nodes (Apple's too, flagged). Returns (nodes, INSTALLED_ON, INSTALLED_BY)."""
    if not packages:
        return 0, 0, 0
    records = _package_records(packages, scan_id)
    installed_on = session.run(
        """
        UNWIND $records AS r
        MERGE (ip:InstalledPackage {package_key: r.package_key})
        SET ip.package_id = r.package_id,
            ip.version = r.version,
            ip.install_date = r.install_date,
            ip.install_prefix = r.install_prefix,
            ip.install_process = r.install_process,
            ip.package_file_name = r.package_file_name,
            ip.is_apple = r.is_apple,
            ip.scan_id = $scan_id
        WITH ip
        MATCH (c:Computer {computer_key: $computer_key})
        MERGE (ip)-[rel:INSTALLED_ON]->(c)
        RETURN count(rel) AS n
        """,
        records=records,
        scan_id=scan_id,
        computer_key=_computer_key(scan_id, hostname),
    ).single()["n"]
    pairs = _installed_by_pairs(records, applications)
    installed_by = 0
    if pairs:
        installed_by = session.run(
            """
            UNWIND $pairs AS pair
            MATCH (ip:InstalledPackage {package_key: pair.package_key})
            MATCH (a:Application {scan_id: $scan_id, bundle_id: pair.bundle_id})
            MERGE (a)-[rel:INSTALLED_BY]->(ip)
            RETURN count(rel) AS n
            """,
            pairs=pairs,
            scan_id=scan_id,
        ).single()["n"]
    return len(records), installed_on, installed_by
