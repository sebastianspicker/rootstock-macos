"""Certificate authority node imports for application signing chains."""

from __future__ import annotations

from neo4j import Session

from models import ApplicationData


def import_certificate_authorities(
    session: Session, apps: list[ApplicationData], scan_id: str
) -> tuple[int, int, int]:
    """
    Extract CertificateAuthority nodes from application certificate chains.
    Creates SIGNED_BY_CA (Application -> CA) and ISSUED_BY (CA -> CA) edges.
    Returns (ca_nodes, signed_by_ca_edges, issued_by_edges).
    """
    ca_records = _certificate_authority_records(apps)
    if not ca_records:
        return 0, 0, 0

    _merge_certificate_authority_nodes(session, ca_records)
    signed_by_count = _link_signed_by_ca_edges(
        session,
        _signed_by_ca_records(apps, scan_id),
    )
    issued_by_count = _link_issued_by_edges(session, _issued_by_records(apps))
    return len(ca_records), signed_by_count, issued_by_count


def _certificate_authority_records(
    apps: list[ApplicationData],
) -> list[dict[str, object]]:
    unique_cas: dict[str, dict[str, object]] = {}
    for app in apps:
        for cert in app.certificate_chain:
            unique_cas.setdefault(
                cert.sha256,
                {
                    "sha256": cert.sha256,
                    "common_name": cert.common_name,
                    "organization": cert.organization,
                    "is_root": cert.is_root,
                    "valid_from": cert.valid_from,
                    "valid_to": cert.valid_to,
                },
            )
    return list(unique_cas.values())


def _merge_certificate_authority_nodes(
    session: Session,
    records: list[dict[str, object]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (ca:CertificateAuthority {sha256: r.sha256})
        SET ca.common_name  = r.common_name,
            ca.organization = r.organization,
            ca.is_root      = r.is_root,
            ca.valid_from   = r.valid_from,
            ca.valid_to     = r.valid_to
        """,
        records=records,
    )


def _signed_by_ca_records(
    apps: list[ApplicationData],
    scan_id: str,
) -> list[dict[str, object]]:
    return [
        {
            "scan_id": scan_id,
            "bundle_id": app.bundle_id,
            "path": app.path,
            "sha256": app.certificate_chain[0].sha256,
        }
        for app in apps
        if app.certificate_chain
    ]


def _link_signed_by_ca_edges(
    session: Session,
    records: list[dict[str, object]],
) -> int:
    if not records:
        return 0
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (a:Application {scan_id: r.scan_id, bundle_id: r.bundle_id, path: r.path})
        MATCH (ca:CertificateAuthority {sha256: r.sha256})
        MERGE (a)-[rel:SIGNED_BY_CA]->(ca)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    return result.single()["n"]


def _issued_by_records(apps: list[ApplicationData]) -> list[dict[str, object]]:
    records = []
    for app in apps:
        chain = app.certificate_chain
        for i in range(len(chain) - 1):
            records.append(
                {
                    "child_sha256": chain[i].sha256,
                    "parent_sha256": chain[i + 1].sha256,
                }
            )
    return records


def _link_issued_by_edges(
    session: Session,
    records: list[dict[str, object]],
) -> int:
    if not records:
        return 0
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (child:CertificateAuthority {sha256: r.child_sha256})
        MATCH (parent:CertificateAuthority {sha256: r.parent_sha256})
        MERGE (child)-[rel:ISSUED_BY]->(parent)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    return result.single()["n"]
