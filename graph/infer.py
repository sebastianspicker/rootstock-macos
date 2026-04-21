#!/usr/bin/env python3
"""
infer.py — Run all Rootstock inference modules to derive attack-path relationships.

Usage:
    python3 graph/infer.py [--neo4j bolt://localhost:7687] [--user neo4j] [--password rootstock]

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


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Rootstock graph inference")
    add_neo4j_args(parser)
    args = parser.parse_args()

    driver = connect_from_args(args)

    print("\n" + "=" * 60)
    print("  ROOTSTOCK INFERENCE ENGINE")
    print("=" * 60)

    print("\n--- Attack Path Discovery " + "─" * 34)
    with driver.session() as session:
        n_inject = infer_injection.infer(session)
        print(f"  CAN_INJECT_INTO:       {n_inject:>4} edges")

        n_inherit = infer_electron.infer(session)
        print(f"  CHILD_INHERITS_TCC:    {n_inherit:>4} edges")

        n_apple_events = infer_automation.infer(session)
        print(f"  CAN_SEND_APPLE_EVENT:  {n_apple_events:>4} edges")

        n_transitive_fda = infer_finder_fda.infer(session)
        print(f"  HAS_TRANSITIVE_FDA:    {n_transitive_fda:>4} edges")

        print("\n--- Escalation & Lateral Movement " + "─" * 25)

        n_mdm_overgrant = infer_mdm_overgrant.infer(session)
        print(f"  MDM_OVERGRANT:         {n_mdm_overgrant:>4} edges")

        n_keychain_groups = infer_keychain_groups.infer(session)
        print(f"  SHARES_KEYCHAIN_GROUP: {n_keychain_groups:>4} edges")

        n_file_acl = infer_file_acl.infer(session)
        print(f"  FILE_ACL:              {n_file_acl:>4} edges")

        n_shell_hooks = infer_shell_hooks.infer(session)
        print(f"  CAN_INJECT_SHELL:      {n_shell_hooks:>4} edges")

        n_a11y = infer_accessibility.infer(session)
        print(f"  CAN_CONTROL_VIA_A11Y:  {n_a11y:>4} edges")

        n_esf = infer_esf.infer(session)
        print(f"  CAN_BLIND_MONITORING:  {n_esf:>4} edges")

        n_group_cap = infer_group_capabilities.infer(session)
        print(f"  CAN_DEBUG:             {n_group_cap:>4} edges")

        n_password = infer_password.infer(session)
        print(f"  CAN_CHANGE_PASSWORD:   {n_password:>4} edges")

        n_kerberos = infer_kerberos.infer(session)
        print(f"  CAN_READ_KERBEROS:     {n_kerberos:>4} edges")

        print("\n--- Sandbox & Gatekeeper " + "─" * 36)

        n_sandbox = infer_sandbox.infer(session)
        print(f"  SANDBOX:               {n_sandbox:>4} edges")

        n_quarantine = infer_quarantine.infer(session)
        print(f"  BYPASSED_GATEKEEPER:   {n_quarantine:>4} edges")

        print("\n--- Risk Scoring & Recommendations " + "─" * 24)

        n_risk = infer_risk_score.infer(session)
        print(f"  RISK_SCORE:            {n_risk:>4} apps scored")

        n_recs = infer_recommendations.infer(session)
        print(f"  HAS_RECOMMENDATION:    {n_recs:>4} edges")

    driver.close()

    total = (n_inject + n_inherit + n_apple_events + n_transitive_fda
             + n_mdm_overgrant + n_keychain_groups + n_file_acl + n_shell_hooks
             + n_a11y + n_esf + n_group_cap + n_password + n_kerberos
             + n_sandbox + n_quarantine + n_recs)
    print("\n" + "=" * 60)
    print("  INFERENCE COMPLETE")
    print("=" * 60)
    print(f"  Total inferred edges:  {total:>5}")
    print(f"  Apps risk-scored:      {n_risk:>5}")
    print(f"  Recommendations:       {n_recs:>5}")
    print("=" * 60)
    if total == 0:
        print("  Note: No inferred edges created.")
        print("  Import scan data first: python3 graph/import.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
