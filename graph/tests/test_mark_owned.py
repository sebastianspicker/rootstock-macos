from __future__ import annotations

from unittest import TestCase

import sys

import mark_owned


checks = TestCase()


class FakeResult:
    def __init__(self, count: int):
        self.count = count

    def single(self):
        return {"n": self.count}


class FakeSession:
    def __init__(self, count: int):
        self.count = count

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, *_args, **_kwargs):
        return FakeResult(self.count)


class FakeDriver:
    def __init__(self, count: int):
        self.count = count
        self.closed = False

    def session(self):
        return FakeSession(self.count)

    def close(self):
        self.closed = True


def run_main(monkeypatch, args: list[str], driver: FakeDriver):
    monkeypatch.setattr(sys, "argv", ["mark_owned.py", *args])
    monkeypatch.setattr(mark_owned, "connect_from_args", lambda _args: driver)

    return mark_owned.main()


def test_invalid_label_returns_nonzero_before_connecting(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["mark_owned.py", "--label", "NotARealLabel", "--key", "fixture"],
    )

    def fail_connect(_args):
        raise AssertionError("invalid labels should not connect")

    monkeypatch.setattr(mark_owned, "connect_from_args", fail_connect)

    checks.assertEqual(mark_owned.main(), 1)
    checks.assertIn("Unknown label 'NotARealLabel'", capsys.readouterr().err)


def test_zero_bundle_match_returns_nonzero(monkeypatch, capsys):
    driver = FakeDriver(count=0)

    exit_code = run_main(monkeypatch, ["--bundle-id", "com.missing.app"], driver)

    captured = capsys.readouterr()
    checks.assertEqual(exit_code, 1)
    checks.assertIs(driver.closed, True)
    checks.assertIn("Marked 0 Application node(s) as owned.", captured.out)
    checks.assertIn("ERROR: No matching nodes found", captured.err)


def test_zero_username_match_returns_nonzero(monkeypatch, capsys):
    driver = FakeDriver(count=0)

    exit_code = run_main(monkeypatch, ["--username", "missing-user"], driver)

    captured = capsys.readouterr()
    checks.assertEqual(exit_code, 1)
    checks.assertIs(driver.closed, True)
    checks.assertIn("Marked 0 User node(s) as owned.", captured.out)
    checks.assertIn("ERROR: No matching nodes found", captured.err)


def test_allow_zero_keeps_explicit_noop_successful(monkeypatch, capsys):
    driver = FakeDriver(count=0)

    exit_code = run_main(
        monkeypatch,
        ["--bundle-id", "com.missing.app", "--allow-zero"],
        driver,
    )

    captured = capsys.readouterr()
    checks.assertEqual(exit_code, 0)
    checks.assertIs(driver.closed, True)
    checks.assertIn("Marked 0 Application node(s) as owned.", captured.out)
    checks.assertIn("WARNING: No matching nodes found", captured.err)


def test_nonzero_match_returns_success(monkeypatch, capsys):
    driver = FakeDriver(count=2)

    exit_code = run_main(monkeypatch, ["--bundle-id", "com.example.app"], driver)

    checks.assertEqual(exit_code, 0)
    checks.assertIs(driver.closed, True)
    checks.assertIn("Marked 2 Application node(s) as owned.", capsys.readouterr().out)
