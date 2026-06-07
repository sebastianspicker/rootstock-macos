from __future__ import annotations

from unittest import TestCase

from unittest.mock import MagicMock

from infer_file_acl import infer


checks = TestCase()


def test_infer_file_acl_runs_all_can_write_rules_with_reasons() -> None:
    session = MagicMock()
    results = []
    for count in [1, 2, 3, 4, 5, 6]:
        result = MagicMock()
        result.single.return_value = {"n": count}
        results.append(result)
    session.run.side_effect = results

    total = infer(session)

    checks.assertEqual(total, sum(range(1, 7)))
    can_write_calls = [
        call
        for call in session.run.call_args_list
        if "MERGE (u)-[r:CAN_WRITE]" in call.args[0]
    ]
    checks.assertEqual(
        [call.kwargs["reason"] for call in can_write_calls],
        [
            "owner_writable",
            "group_writable",
            "world_writable",
        ],
    )
