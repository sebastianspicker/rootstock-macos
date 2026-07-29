#!/usr/bin/env python3
"""
infer.py - Run all Rootstock inference modules to derive attack-path relationships.

Usage:
    python3 graph/infer.py
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

from neo4j_connection import add_neo4j_args, connect_from_args
import infer_injection
import infer_electron
import infer_automation
import infer_finder_fda
import infer_mdm_overgrant
import infer_keychain_groups
import infer_file_acl
import infer_shell_hooks
import infer_accessibility
import infer_esf
import infer_group_capabilities
import infer_password
import infer_kerberos
import infer_sandbox
import infer_quarantine
import infer_risk_score
import infer_recommendations


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
        "password": infer_password.infer(session),
        "kerberos": infer_kerberos.infer(session),
    }
    print(f"  MDM_OVERGRANT:         {counts['mdm_overgrant']:>4} edges")
    print(f"  SHARES_KEYCHAIN_GROUP: {counts['keychain_groups']:>4} edges")
    print(f"  FILE_ACL:              {counts['file_acl']:>4} edges")
    print(f"  CAN_INJECT_SHELL:      {counts['shell_hooks']:>4} edges")
    print(f"  CAN_CONTROL_VIA_A11Y:  {counts['a11y']:>4} edges")
    print(f"  CAN_BLIND_MONITORING:  {counts['esf']:>4} edges")
    print(f"  CAN_DEBUG:             {counts['group_cap']:>4} edges")
    print(f"  CAN_CHANGE_PASSWORD:   {counts['password']:>4} edges")
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


def _run_risk_inference(session) -> dict[str, int]:
    print("\n--- Risk Scoring & Recommendations " + "─" * 24)
    counts = {
        "risk": infer_risk_score.infer(session),
        "recs": infer_recommendations.infer(session),
    }
    print(f"  RISK_SCORE:            {counts['risk']:>4} apps scored")
    print(f"  HAS_RECOMMENDATION:    {counts['recs']:>4} edges")
    return counts


def _run_all_inference(session) -> dict[str, int]:
    counts: dict[str, int] = {}
    counts.update(_run_attack_path_inference(session))
    counts.update(_run_escalation_inference(session))
    counts.update(_run_sandbox_inference(session))
    counts.update(_run_risk_inference(session))
    return counts


def _inferred_edge_total(counts: dict[str, int]) -> int:
    excluded = {"risk"}
    return sum(value for key, value in counts.items() if key not in excluded)


def _print_completion_summary(counts: dict[str, int], total: int) -> None:
    print("\n" + "=" * 60)
    print("  INFERENCE COMPLETE")
    print("=" * 60)
    print(f"  Total inferred edges:  {total:>5}")
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
    args = parser.parse_args()

    driver = connect_from_args(args)

    print("\n" + "=" * 60)
    print("  ROOTSTOCK INFERENCE ENGINE")
    print("=" * 60)

    with driver.session() as session:
        counts = _run_all_inference(session)

    driver.close()

    total = _inferred_edge_total(counts)
    _print_completion_summary(counts, total)
    if total == 0:
        print("  Note: No inferred edges created.")
        print("  Import scan data first: python3 graph/import_scan.py")
        if not args.allow_empty:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
