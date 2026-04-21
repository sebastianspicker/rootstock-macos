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

    # Enrich Computer node with AD properties
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
        computer_key=f"{scan_id}:{hostname}" if scan_id is not None else None,
        realm=ad_binding.realm,
        forest=ad_binding.forest,
        computer_account=ad_binding.computer_account,
        ou=ad_binding.organizational_unit,
        preferred_dc=ad_binding.preferred_dc,
    )

    # AD_USER_OF: User{is_ad_user} → Computer{ad_bound}
    # Connects floating AD user nodes to the host they were discovered on.
    session.run(
        """
        MATCH (u:User {is_ad_user: true})
        MATCH (c:Computer {computer_key: $computer_key, ad_bound: true})
        MERGE (u)-[:AD_USER_OF]->(c)
        """,
        computer_key=f"{scan_id}:{hostname}" if scan_id is not None else None,
    )

    if not ad_binding.group_mappings:
        return 0, 0

    records = [
        {
            "ad_group": m.ad_group,
            "local_group": m.local_group,
        }
        for m in ad_binding.group_mappings
    ]

    # MERGE ADGroup nodes
    session.run(
        """
        UNWIND $records AS r
        MERGE (ag:ADGroup {name: r.ad_group})
        """,
        records=records,
    )

    # MAPPED_TO: ADGroup → LocalGroup
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
    edges = result.single()["n"]

    return len(ad_binding.group_mappings), edges


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

    records = [
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
            # krb5.conf parsed fields
            "default_realm": a.default_realm,
            "permitted_enc_types": a.permitted_enc_types,
            "realm_names": a.realm_names,
            "is_forwardable": a.is_forwardable,
        }
        for a in artifacts
    ]

    # MERGE KerberosArtifact nodes
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

    # FOUND_ON: KerberosArtifact → Computer
    result = session.run(
        """
        UNWIND $records AS r
        MATCH (ka:KerberosArtifact {path: r.path})
        MATCH (c:Computer {computer_key: $computer_key})
        MERGE (ka)-[rel:FOUND_ON]->(c)
        RETURN count(rel) AS n
        """,
        records=records,
        computer_key=f"{scan_id}:{hostname}" if scan_id is not None else None,
    )
    found_on = result.single()["n"]

    # HAS_KERBEROS_CACHE: User → KerberosArtifact (ccache with principal_hint)
    ccache_records = [
        r for r in records if r["artifact_type"] == "ccache" and r["principal_hint"]
    ]
    has_cache = 0
    if ccache_records:
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
        has_cache = result.single()["n"]

    # HAS_KEYTAB: Computer → KerberosArtifact (keytab type)
    keytab_records = [r for r in records if r["artifact_type"] == "keytab"]
    has_keytab = 0
    if keytab_records:
        result = session.run(
            """
            UNWIND $records AS r
            MATCH (ka:KerberosArtifact {path: r.path})
            MATCH (c:Computer {computer_key: $computer_key})
            MERGE (c)-[rel:HAS_KEYTAB]->(ka)
            RETURN count(rel) AS n
            """,
            records=keytab_records,
            computer_key=f"{scan_id}:{hostname}" if scan_id is not None else None,
        )
        has_keytab = result.single()["n"]

    return len(artifacts), found_on, has_cache, has_keytab
