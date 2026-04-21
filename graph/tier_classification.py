#!/usr/bin/env python3
"""
tier_classification.py — Classify Application nodes into Tier 0/1/2 based on security impact.

Tier definitions:
  - Tier 0 (Crown Jewels): FDA apps, com.apple.private.tcc.allow holders, SUDO_NOPASSWD targets
  - Tier 1 (Privileged):   Any allowed TCC grant, trusted Keychain ACL apps, root-running daemons
  - Tier 2 (Interesting):  Persistence items, injectable apps, apps with private entitlements

Sets `tier: 0|1|2` property on Application nodes. Higher-priority tier wins
(an app matching both Tier 0 and Tier 1 criteria gets Tier 0).

Usage:
    python3 graph/tier_classification.py [--neo4j bolt://localhost:7687]

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import sys

from neo4j_connection import add_neo4j_args, connect_from_args
from constants import TIER_PROPERTY


def classify_tier0(session) -> int:
    """
    Tier 0 — Crown Jewels. Compromise = game over.
      - Apps with Full Disk Access grant
      - Apps holding com.apple.private.tcc.allow entitlement
      - Apps targeted by SUDO_NOPASSWD rules
    """
    result = session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{TIER_PROPERTY} IS NULL
        AND (
            // Has Full Disk Access
            EXISTS {{
                MATCH (app)-[:HAS_TCC_GRANT {{allowed: true}}]->(:TCC_Permission {{service: 'kTCCServiceSystemPolicyAllFiles'}})
            }}
            OR
            // Holds private TCC allow entitlement
            EXISTS {{
                MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement {{name: 'com.apple.private.tcc.allow'}})
            }}
            OR
            // Is a SUDO_NOPASSWD target (via launch item running as user with sudo)
            EXISTS {{
                MATCH (app)-[:PERSISTS_VIA]->(:LaunchItem)-[:RUNS_AS]->(u:User)-[:SUDO_NOPASSWD]->()
            }}
        )
        SET app.{TIER_PROPERTY} = 0
        RETURN count(app) AS n
        """
    )
    return result.single()["n"]


def classify_tier1(session) -> int:
    """
    Tier 1 — Privileged access. Valuable targets worth protecting.
      - Apps with any allowed TCC grant (non-FDA — those are Tier 0)
      - Apps trusted in Keychain ACLs
      - Apps persisting as root-running daemons
    """
    result = session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{TIER_PROPERTY} IS NULL
        AND (
            // Has any allowed TCC grant
            EXISTS {{
                MATCH (app)-[:HAS_TCC_GRANT {{allowed: true}}]->(:TCC_Permission)
            }}
            OR
            // Trusted in a Keychain ACL
            EXISTS {{
                MATCH (app)-[:CAN_READ_KEYCHAIN]->(:Keychain_Item)
            }}
            OR
            // Persists via root-running daemon
            EXISTS {{
                MATCH (app)-[:PERSISTS_VIA]->(li:LaunchItem {{type: 'daemon'}})-[:RUNS_AS]->(:User {{name: 'root'}})
            }}
        )
        SET app.{TIER_PROPERTY} = 1
        RETURN count(app) AS n
        """
    )
    return result.single()["n"]


def classify_tier2(session) -> int:
    """
    Tier 2 — Interesting. Stepping stones or indicators of risk.
      - Apps with persistence mechanisms (any launch item)
      - Injectable apps (non-empty injection_methods)
      - Apps with private Apple entitlements
    """
    result = session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{TIER_PROPERTY} IS NULL
        AND (
            // Has a persistence mechanism
            EXISTS {{
                MATCH (app)-[:PERSISTS_VIA]->(:LaunchItem)
            }}
            OR
            // Is injectable
            size(app.injection_methods) > 0
            OR
            // Has private entitlements
            EXISTS {{
                MATCH (app)-[:HAS_ENTITLEMENT]->(:Entitlement {{is_private: true}})
            }}
        )
        SET app.{TIER_PROPERTY} = 2
        RETURN count(app) AS n
        """
    )
    return result.single()["n"]


def classify_tier0_cve(session) -> int:
    """
    Tier 0 CVE promotion — apps with CISA KEV CVEs and any TCC grant.

    Graceful degradation: returns 0 if no Vulnerability nodes exist.
    """
    result = session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{TIER_PROPERTY} IS NULL
        AND EXISTS {{ MATCH (app)-[:AFFECTED_BY]->(v:Vulnerability {{in_kev: true}}) }}
        AND EXISTS {{ MATCH (app)-[:HAS_TCC_GRANT {{allowed: true}}]->(:TCC_Permission) }}
        SET app.{TIER_PROPERTY} = 0
        RETURN count(app) AS n
        """
    )
    return result.single()["n"]


def classify_tier1_cve(session) -> int:
    """
    Tier 1 CVE promotion — apps with high-CVSS CVEs (>=8.0) and any TCC grant.

    Graceful degradation: returns 0 if no Vulnerability nodes exist.
    """
    result = session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{TIER_PROPERTY} IS NULL
        AND EXISTS {{ MATCH (app)-[:AFFECTED_BY]->(v:Vulnerability) WHERE v.cvss_score >= 8.0 }}
        AND EXISTS {{ MATCH (app)-[:HAS_TCC_GRANT {{allowed: true}}]->(:TCC_Permission) }}
        SET app.{TIER_PROPERTY} = 1
        RETURN count(app) AS n
        """
    )
    return result.single()["n"]


def classify_tier2_cve(session) -> int:
    """
    Tier 2 CVE promotion — any app with a CVE association.

    Graceful degradation: returns 0 if no Vulnerability nodes exist.
    """
    result = session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{TIER_PROPERTY} IS NULL
        AND EXISTS {{ MATCH (app)-[:AFFECTED_BY]->(:Vulnerability) }}
        SET app.{TIER_PROPERTY} = 2
        RETURN count(app) AS n
        """
    )
    return result.single()["n"]


def classify(session) -> tuple[int, int, int]:
    """
    Run all tier classifications in priority order (Tier 0 first).

    Interleaves structural and CVE-aware classification at each tier level:
    tier0_structural → tier0_cve → tier1_structural → tier1_cve → tier2_structural → tier2_cve

    Returns (tier0_count, tier1_count, tier2_count) — combined structural + CVE.
    """
    # Clear existing tiers to allow reclassification
    session.run(
        f"""
        MATCH (app:Application)
        WHERE app.{TIER_PROPERTY} IS NOT NULL
        REMOVE app.{TIER_PROPERTY}
        """
    )

    t0 = classify_tier0(session) + classify_tier0_cve(session)
    t1 = classify_tier1(session) + classify_tier1_cve(session)
    t2 = classify_tier2(session) + classify_tier2_cve(session)
    return t0, t1, t2


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Classify Application nodes into Tier 0/1/2")
    add_neo4j_args(parser)
    args = parser.parse_args()

    driver = connect_from_args(args)

    print("Running tier classification...")
    with driver.session() as session:
        t0, t1, t2 = classify(session)
        row = session.run(
            f"MATCH (a:Application) WHERE a.{TIER_PROPERTY} IS NULL RETURN count(a) AS n"
        ).single()
        unclassified = row["n"]

    driver.close()

    total = t0 + t1 + t2
    print(f"  Tier 0 (Crown Jewels): {t0}")
    print(f"  Tier 1 (Privileged):   {t1}")
    print(f"  Tier 2 (Interesting):  {t2}")
    print(f"  Unclassified:          {unclassified}")
    print(f"  Total classified:      {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
