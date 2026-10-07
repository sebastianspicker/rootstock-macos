#!/usr/bin/env python3
"""
rootstock-graph-infer - Run all Rootstock inference modules to derive attack-path relationships.

Usage:
    rootstock-graph-infer
        [--neo4j bolt://localhost:7687]
        [--neo4j-user neo4j]
        [--neo4j-password <password>]  # or NEO4J_PASSWORD

All inferred edges carry {inferred: true} to distinguish them from explicit collector data.
Idempotent: safe to re-run on the same graph.

Exit code 0 on success, 1 on failure.
"""

from __future__ import annotations

import argparse
import sys

from ..neo4j import add_neo4j_args, connect_from_args
from . import infer_injection
from . import infer_electron
from . import infer_automation
from . import infer_finder_fda
from . import infer_mdm_overgrant
from . import infer_keychain_groups
from . import infer_file_acl
from . import infer_shell_hooks
from . import infer_accessibility
from . import infer_esf
from . import infer_group_capabilities
from . import infer_password
from . import infer_kerberos
from . import infer_sandbox
from . import infer_quarantine
from . import infer_risk_score
from . import infer_recommendations
from .tier_classification import classify


def _run_attack_path_inference(session) -> dict[str, int]:
    print("\n--- Attack Path Discovery " + "─" * 34)
    counts = {
        "inject": infer_injection.infer(session),
        "inherit": infer_electron.infer(session),
        "apple_events": infer_automation.infer(session),
        "transitive_fda": infer_finder_fda.infer(session),
    }
    print(f"  CAN_INJECT_INTO:       {counts['inject']:>4} edges")
    print(f"  CHILD_INHERITS_TCC:    {counts['inherit']:>4} edges")
    print(f"  CAN_SEND_APPLE_EVENT:  {counts['apple_events']:>4} edges")
    print(f"  HAS_TRANSITIVE_FDA:    {counts['transitive_fda']:>4} edges")
    return counts


def _run_escalation_inference(session) -> dict[str, int]:
    print("\n--- Escalation & Lateral Movement " + "─" * 25)
    counts = {
        "mdm_overgrant": infer_mdm_overgrant.infer(session),
        "keychain_groups": infer_keychain_groups.infer(session),
        "file_acl": infer_file_acl.infer(session),
        "shell_hooks": infer_shell_hooks.infer(session),
        "a11y": infer_accessibility.infer(session),
        "esf": infer_esf.infer(session),
        "group_cap": infer_group_capabilities.infer(session),
        "credential_change": infer_password.infer(session),
        "kerberos": infer_kerberos.infer(session),
    }
    print(f"  MDM_OVERGRANT:         {counts['mdm_overgrant']:>4} edges")
    print(f"  SHARES_KEYCHAIN_GROUP: {counts['keychain_groups']:>4} edges")
    print(f"  FILE_ACL:              {counts['file_acl']:>4} edges")
    print(f"  CAN_INJECT_SHELL:      {counts['shell_hooks']:>4} edges")
    print(f"  CAN_CONTROL_VIA_A11Y:  {counts['a11y']:>4} edges")
    print(f"  CAN_BLIND_MONITORING:  {counts['esf']:>4} edges")
    print(f"  CAN_DEBUG:             {counts['group_cap']:>4} edges")
    print(f"  CAN_CHANGE_PASSWORD:   {counts['credential_change']:>4} edges")
    print(f"  CAN_READ_KERBEROS:     {counts['kerberos']:>4} edges")
    return counts


def _run_sandbox_inference(session) -> dict[str, int]:
    print("\n--- Sandbox & Gatekeeper " + "─" * 36)
    counts = {
        "sandbox": infer_sandbox.infer(session),
        "quarantine": infer_quarantine.infer(session),
    }
    print(f"  SANDBOX:               {counts['sandbox']:>4} edges")
    print(f"  BYPASSED_GATEKEEPER:   {counts['quarantine']:>4} edges")
    return counts


def _run_tier_classification(session) -> dict[str, int]:
    print("\n--- Tier Classification " + "─" * 37)
    t0, t1, t2 = classify(session)
    print(f"  Tier 0 (Crown Jewels): {t0:>4} apps")
    print(f"  Tier 1 (Privileged):   {t1:>4} apps")
    print(f"  Tier 2 (Interesting):  {t2:>4} apps")
    return {"tier0": t0, "tier1": t1, "tier2": t2}


def _run_risk_inference(session) -> dict[str, int]:
    print("\n--- Risk Scoring & Recommendations " + "─" * 24)
    counts = {
        "risk": infer_risk_score.infer(session),
        "recs": infer_recommendations.infer(session),
    }
    print(f"  RISK_SCORE:            {counts['risk']:>4} apps scored")
    print(f"  HAS_RECOMMENDATION:    {counts['recs']:>4} edges")
    return counts


STAGES = ("edges", "score", "all")


def _run_all_inference(session, stage: str = "all") -> dict[str, int]:
    """Run the edge stage, the scoring stage, or both.

    The scoring stage (tier classification, risk scores, recommendations) reads
    AFFECTED_BY edges, while the vulnerability importer's category heuristics read
    inferred edges. pipeline.sh therefore runs ``--stage edges``, imports
    vulnerabilities, then runs ``--stage score``.
    """
    counts: dict[str, int] = {}
    if stage in ("edges", "all"):
        counts.update(_run_attack_path_inference(session))
        counts.update(_run_escalation_inference(session))
        counts.update(_run_sandbox_inference(session))
    if stage in ("score", "all"):
        counts.update(_run_tier_classification(session))
        counts.update(_run_risk_inference(session))
    return counts


def _inferred_edge_total(counts: dict[str, int]) -> int:
    excluded = {"risk", "tier0", "tier1", "tier2"}
    return sum(value for key, value in counts.items() if key not in excluded)


def _print_completion_summary(counts: dict[str, int], total: int) -> None:
    print("\n" + "=" * 60)
    print("  INFERENCE COMPLETE")
    print("=" * 60)
    print(f"  Total inferred edges:  {total:>5}")
    if "risk" in counts:
        print(f"  Apps risk-scored:      {counts['risk']:>5}")
        print(f"  Recommendations:       {counts['recs']:>5}")
    print("=" * 60)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Rootstock graph inference")
    add_neo4j_args(parser)
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="Exit successfully when no inferred edges are created.",
    )
    parser.add_argument(
        "--stage",
        choices=STAGES,
        default="all",
        help=(
            "edges: relationship inference only; score: tier classification, risk "
            "scores and recommendations only; all (default): both in order."
        ),
    )
    args = parser.parse_args()

    driver = connect_from_args(args)

    print("\n" + "=" * 60)
    print("  ROOTSTOCK INFERENCE ENGINE")
    print("=" * 60)

    with driver.session() as session:
        counts = _run_all_inference(session, args.stage)

    driver.close()

    total = _inferred_edge_total(counts)
    _print_completion_summary(counts, total)
    if total == 0 and args.stage != "score":
        print("  Note: No inferred edges created.")
        print("  Import scan data first: rootstock-graph-import-scan")
        if not args.allow_empty:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
