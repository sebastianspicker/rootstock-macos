"""import_nodes_security_enterprise.py — AD binding and Kerberos artifact imports."""

from __future__ import annotations

import logging

from neo4j import Session

from models import ADBindingData, KerberosArtifactData

logger = logging.getLogger(__name__)


def import_ad_binding(
    session: Session,
    ad_binding: ADBindingData | None,
    hostname: str,
    scan_id: str | None = None,
) -> tuple[int, int]:
    """
    Enrich Computer node with AD binding properties, create ADGroup nodes
    and MAPPED_TO edges from ADGroup → LocalGroup.

    Returns (adgroup_nodes, mapped_to_edges).
    """
    if ad_binding is None or not ad_binding.is_bound:
        return 0, 0

    computer_key = _computer_key(hostname, scan_id)
    _enrich_computer_ad_binding(session, ad_binding, computer_key)
    _link_ad_users_to_computer(session, computer_key)

    if not ad_binding.group_mappings:
        return 0, 0

    records = _ad_group_mapping_records(ad_binding)
    _merge_ad_group_nodes(session, records)
    edges = _link_ad_group_mappings(session, records)
    return len(ad_binding.group_mappings), edges


def _enrich_computer_ad_binding(
    session: Session,
    ad_binding: ADBindingData,
    computer_key: str | None,
) -> None:
    session.run(
        """
        MATCH (c:Computer {computer_key: $computer_key})
        SET c.ad_bound = true,
            c.ad_realm = $realm,
            c.ad_forest = $forest,
            c.ad_computer_account = $computer_account,
            c.ad_ou = $ou,
            c.ad_preferred_dc = $preferred_dc
        """,
        computer_key=computer_key,
        realm=ad_binding.realm,
        forest=ad_binding.forest,
        computer_account=ad_binding.computer_account,
        ou=ad_binding.organizational_unit,
        preferred_dc=ad_binding.preferred_dc,
    )


def _link_ad_users_to_computer(session: Session, computer_key: str | None) -> None:
    session.run(
        """
        MATCH (u:User {is_ad_user: true})
        MATCH (c:Computer {computer_key: $computer_key, ad_bound: true})
        MERGE (u)-[:AD_USER_OF]->(c)
        """,
        computer_key=computer_key,
    )


def _ad_group_mapping_records(ad_binding: ADBindingData) -> list[dict[str, str]]:
    return [
        {
            "ad_group": m.ad_group,
            "local_group": m.local_group,
        }
        for m in ad_binding.group_mappings
    ]


def _merge_ad_group_nodes(
    session: Session,
    records: list[dict[str, str]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (ag:ADGroup {name: r.ad_group})
        """,
        records=records,
    )


def _link_ad_group_mappings(
    session: Session,
    records: list[dict[str, str]],
) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (ag:ADGroup {name: r.ad_group})
        MATCH (lg:LocalGroup {name: r.local_group})
        MERGE (ag)-[rel:MAPPED_TO]->(lg)
        RETURN count(rel) AS n
        """,
        records=records,
    )
    return result.single()["n"]


def _computer_key(hostname: str, scan_id: str | None) -> str | None:
    return f"{scan_id}:{hostname}" if scan_id is not None else None


def _kerberos_artifact_records(
    artifacts: list[KerberosArtifactData],
) -> list[dict[str, object]]:
    return [
        {
            "path": a.path,
            "artifact_type": a.artifact_type,
            "owner": a.owner,
            "group": a.group,
            "mode": a.mode,
            "modification_time": a.modification_time,
            "principal_hint": a.principal_hint,
            "is_readable": a.is_readable,
            "is_world_readable": a.is_world_readable,
            "is_group_readable": a.is_group_readable,
            "default_realm": a.default_realm,
            "permitted_enc_types": a.permitted_enc_types,
            "realm_names": a.realm_names,
            "is_forwardable": a.is_forwardable,
        }
        for a in artifacts
    ]


def _import_kerberos_artifact_nodes(
    session: Session,
    records: list[dict[str, object]],
) -> None:
    session.run(
        """
        UNWIND $records AS r
        MERGE (ka:KerberosArtifact {path: r.path})
        SET ka.artifact_type      = r.artifact_type,
            ka.owner              = r.owner,
            ka.group_name         = r.group,
            ka.mode               = r.mode,
            ka.modification_time  = r.modification_time,
            ka.principal_hint     = r.principal_hint,
            ka.is_readable        = r.is_readable,
            ka.is_world_readable  = r.is_world_readable,
            ka.is_group_readable  = r.is_group_readable,
            ka.default_realm      = r.default_realm,
            ka.permitted_enc_types = r.permitted_enc_types,
            ka.realm_names        = r.realm_names,
            ka.is_forwardable     = r.is_forwardable
        """,
        records=records,
    )


def _import_kerberos_found_on_edges(
    session: Session,
    records: list[dict[str, object]],
    computer_key: str | None,
) -> int:
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (ka:KerberosArtifact {path: r.path})
        MATCH (c:Computer {computer_key: $computer_key})
        MERGE (ka)-[rel:FOUND_ON]->(c)
        RETURN count(rel) AS n
        """,
        records=records,
        computer_key=computer_key,
    )
    return result.single()["n"]


def _import_kerberos_cache_edges(
    session: Session,
    records: list[dict[str, object]],
) -> int:
    ccache_records = [
        r for r in records if r["artifact_type"] == "ccache" and r["principal_hint"]
    ]
    if not ccache_records:
        return 0

    result = session.run(
        """
        UNWIND $records AS r
        MATCH (ka:KerberosArtifact {path: r.path})
        MERGE (u:User {name: r.principal_hint})
        MERGE (u)-[rel:HAS_KERBEROS_CACHE]->(ka)
        RETURN count(rel) AS n
        """,
        records=ccache_records,
    )
    return result.single()["n"]


def _import_keytab_edges(
    session: Session,
    records: list[dict[str, object]],
    computer_key: str | None,
) -> int:
    keytab_records = [r for r in records if r["artifact_type"] == "keytab"]
    if not keytab_records:
        return 0

    result = session.run(
        """
        UNWIND $records AS r
        MATCH (ka:KerberosArtifact {path: r.path})
        MATCH (c:Computer {computer_key: $computer_key})
        MERGE (c)-[rel:HAS_KEYTAB]->(ka)
        RETURN count(rel) AS n
        """,
        records=keytab_records,
        computer_key=computer_key,
    )
    return result.single()["n"]


def import_kerberos_artifacts(
    session: Session,
    artifacts: list[KerberosArtifactData],
    hostname: str,
    scan_id: str | None = None,
) -> tuple[int, int, int, int]:
    """
    MERGE KerberosArtifact nodes and create:
    - FOUND_ON edges (KerberosArtifact → Computer)
    - HAS_KERBEROS_CACHE edges (User → KerberosArtifact) for ccache with principal_hint
    - HAS_KEYTAB edges (Computer → KerberosArtifact) for keytab type

    Returns (artifact_nodes, found_on_edges, has_kerberos_cache_edges, has_keytab_edges).
    """
    if not artifacts:
        return 0, 0, 0, 0

    records = _kerberos_artifact_records(artifacts)
    computer_key = _computer_key(hostname, scan_id)
    _import_kerberos_artifact_nodes(session, records)
    found_on = _import_kerberos_found_on_edges(session, records, computer_key)
    has_cache = _import_kerberos_cache_edges(session, records)
    has_keytab = _import_keytab_edges(session, records, computer_key)

    return len(artifacts), found_on, has_cache, has_keytab
