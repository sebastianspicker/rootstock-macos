"""
infer_recommendations_cve.py - Update recommendations for version-matched CVEs.

Registry CVEs matched precisely to an installed version (``match_tier 'precise'``)
produce one ``patch_<cve_id>`` recommendation per CVE naming the patched version.

NVD matches (``AFFECTED_BY {match_tier: 'cpe'}``) carry no patched version and can be
numerous, so instead of one ``patch_<cve>`` recommendation per CVE they produce:

  - one ``patch_nvd:<bundle_id>`` recommendation per affected app ("update to the latest
    version; NVD lists N matching CVEs"), and
  - one host-scoped ``patch_macos`` recommendation when the Computer's macOS release has
    NVD matches.
"""

from __future__ import annotations

from neo4j import Session

from ..constants import ATTACKER_BUNDLE_ID

_APP_UPDATE_RECOMMENDATIONS = """
    MATCH (app:Application)-[:AFFECTED_BY {match_tier: 'cpe'}]->(v:Vulnerability)
    WHERE app.bundle_id <> $attacker_id
    WITH app,
         count(DISTINCT v) AS cves,
         count(DISTINCT CASE WHEN coalesce(v.in_kev, false) THEN v END) AS kev_cves,
         max(v.cvss_score) AS max_cvss
    MERGE (r:Recommendation {key: 'patch_nvd:' + coalesce(app.scan_id, '') + ':' + app.bundle_id + ':' + coalesce(app.path, '')})
    SET r.category = 'vulnerability',
        r.scope    = 'app',
        r.title    = 'Update ' + app.name,
        r.text     = 'Update ' + app.name + ' to the latest version; NVD lists '
                     + toString(cves) + ' CVE(s) matching the installed version '
                     + coalesce(app.version, 'unknown') + '.'
                     + CASE WHEN kev_cves > 0
                            THEN ' ' + toString(kev_cves) + ' of them are in the CISA Known '
                                 + 'Exploited Vulnerabilities catalog; treat this as urgent.'
                            ELSE '' END,
        r.priority = CASE WHEN kev_cves > 0 OR max_cvss >= 9.0 THEN 'critical' ELSE 'high' END
    MERGE (app)-[:HAS_RECOMMENDATION]->(r)
    RETURN count(*) AS n
"""

_MACOS_UPDATE_RECOMMENDATION = """
    MATCH (c:Computer)-[:AFFECTED_BY {match_tier: 'cpe'}]->(v:Vulnerability)
    WITH c,
         count(DISTINCT v) AS cves,
         count(DISTINCT CASE WHEN coalesce(v.in_kev, false) THEN v END) AS kev_cves
    MERGE (r:Recommendation {key: 'patch_macos:' + c.scan_id})
    SET r.category = 'vulnerability',
        r.scope    = 'host',
        r.title    = 'Install the current macOS update',
        r.text     = 'macOS ' + coalesce(split(c.macos_cpe, ':')[5], c.macos_version, '')
                     + ' has ' + toString(cves) + ' published CVE(s), ' + toString(kev_cves)
                     + ' in CISA KEV; install the current macOS update.',
        r.priority = CASE WHEN kev_cves > 0 THEN 'critical' ELSE 'high' END
    MERGE (c)-[:HAS_RECOMMENDATION]->(r)
    RETURN count(*) AS n
"""


def _count(session: Session, cypher: str, **params) -> int:
    record = session.run(cypher, **params).single()
    return int(record["n"] or 0) if record else 0


def create_nvd_update_recommendations(session: Session) -> int:
    """Create per-app and macOS update recommendations; return HAS_RECOMMENDATION edges."""
    session.run(
        """
        MATCH (r:Recommendation)
        WHERE r.key STARTS WITH 'patch_nvd:' OR r.key STARTS WITH 'patch_macos:' OR r.key = 'patch_macos'
        DETACH DELETE r
        """
    )
    app_edges = _count(session, _APP_UPDATE_RECOMMENDATIONS, attacker_id=ATTACKER_BUNDLE_ID)
    return app_edges + _count(session, _MACOS_UPDATE_RECOMMENDATION)


def create_patch_recommendations(session: Session) -> int:
    """One `patch_<cve>` recommendation per version-matched CVE, naming the fixed version."""
    result = session.run(
        """
        MATCH (app:Application)-[e:AFFECTED_BY]->(v:Vulnerability)
        WHERE coalesce(e.match_tier, 'precise') <> 'cpe'
        WITH v, collect(DISTINCT app) AS apps
        MERGE (r:Recommendation {key: 'patch_' + v.cve_id})
        SET r.category = 'vulnerability',
            r.scope    = 'app',
            r.title    = 'Update to fix ' + v.cve_id,
            r.text     = 'The installed version is affected by ' + v.cve_id + ' (' + v.title + '). '
                         + CASE WHEN v.patched_version IS NOT NULL
                                THEN 'Update to ' + v.patched_version + ' or later.'
                                ELSE 'Update to the current vendor release.' END
                         + CASE WHEN coalesce(v.in_kev, false)
                                THEN ' This CVE is in the CISA Known Exploited Vulnerabilities catalog; treat it as urgent.'
                                ELSE '' END,
            r.priority = CASE WHEN coalesce(v.in_kev, false) OR v.cvss_score >= 9.0 THEN 'critical' ELSE 'high' END
        WITH r, v, apps
        UNWIND apps AS app
        MERGE (app)-[:HAS_RECOMMENDATION]->(r)
        WITH r, v, count(*) AS n
        OPTIONAL MATCH (v)-[:MAPS_TO_TECHNIQUE]->(t:AttackTechnique)
        FOREACH (_ IN CASE WHEN t IS NULL THEN [] ELSE [1] END | MERGE (r)-[:MITIGATES]->(t))
        RETURN sum(n) AS n
        """
    )
    record = result.single()
    return int(record["n"] or 0) if record else 0
