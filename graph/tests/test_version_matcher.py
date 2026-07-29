"""
test_version_matcher.py - Tests for version-aware vulnerability matching.

Pure unit tests - no Neo4j or network calls required.
"""

from __future__ import annotations


import pytest
from unittest import TestCase

from version_matcher import (
    extract_app_max_version,
    extract_macos_max_version,
    extract_patched_macos_version,
    is_affected,
    parse_version_tuple,
    version_lt,
    version_lte,
)


checks = TestCase()


def check_equal(actual, expected) -> None:
    checks.assertEqual(actual, expected)


def check_is(actual, expected) -> None:
    checks.assertIs(actual, expected)


def check_is_none(actual) -> None:
    checks.assertIsNone(actual)


def check_affected(expected: bool, **kwargs) -> None:
    checks.assertIs(is_affected(**kwargs), expected)


# ── Version parsing ──────────────────────────────────────────────────────────


class TestParseVersionTuple:
    def test_simple_major_minor(self):
        check_equal(parse_version_tuple("14.6"), (14, 6))

    def test_major_only(self):
        check_equal(parse_version_tuple("15"), (15,))

    def test_three_part(self):
        check_equal(parse_version_tuple("13.5.2"), (13, 5, 2))

    def test_semver_four_part(self):
        check_equal(parse_version_tuple("127.0.6533.72"), (127, 0, 6533, 72))

    def test_whitespace_stripped(self):
        check_equal(parse_version_tuple("  14.6  "), (14, 6))

    def test_invalid_version_raises(self):
        with pytest.raises(ValueError):
            parse_version_tuple("not-a-version")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            parse_version_tuple("")

    def test_version_with_dash_suffix(self):
        check_equal(parse_version_tuple("27.1.0-beta"), (27, 1, 0, -2))

    def test_version_with_dashed_rc_suffix(self):
        check_equal(parse_version_tuple("1.0.0-rc.1"), (1, 0, 0, -1, 1))

    def test_unsupported_dash_suffix_raises(self):
        with pytest.raises(ValueError):
            parse_version_tuple("1.0.0-preview")

    def test_prerelease_beta(self):
        """15beta3 should parse with pre-release sentinel."""
        result = parse_version_tuple("15beta3")
        check_equal(result[0], 15)
        checks.assertLess(result[1], 0)  # pre-release sentinel is negative

    def test_prerelease_alpha(self):
        result = parse_version_tuple("15alpha1")
        check_equal(result[0], 15)
        checks.assertLess(result[1], 0)

    def test_prerelease_rc(self):
        result = parse_version_tuple("15rc2")
        check_equal(result[0], 15)
        checks.assertLess(result[1], 0)

    def test_prerelease_ordering(self):
        """alpha < beta < rc < release (via version_lt, which pads with zeros)."""
        check_is(version_lt("15alpha1", "15beta1"), True)
        check_is(version_lt("15beta1", "15rc1"), True)
        check_is(version_lt("15rc1", "15.0"), True)
        check_is(version_lt("15alpha1", "15.0"), True)

    def test_prerelease_less_than_release(self):
        """15beta3 < 15.0 must hold."""
        check_is(version_lte("15beta3", "15.0"), True)
        check_is(version_lt("15beta3", "15.0"), True)

    def test_dashed_prerelease_less_than_release(self):
        check_is(version_lt("1.0.0-beta", "1.0.0"), True)
        check_is(version_lt("1.0.0-rc.1", "1.0.0"), True)
        check_is(version_lt("1.0.0-beta", "1.0.0-rc.1"), True)

    def test_release_not_less_than_prerelease(self):
        """15.0 > 15beta3 must hold."""
        check_is(version_lte("15.0", "15beta3"), False)

    def test_release_not_less_than_dashed_prerelease(self):
        check_is(version_lt("1.0.0", "1.0.0-beta"), False)
        check_is(version_lte("1.0.0", "1.0.0-rc.1"), False)


# ── Version comparison ───────────────────────────────────────────────────────


class TestVersionComparison:
    def test_lte_equal(self):
        check_is(version_lte("14.6", "14.6"), True)

    def test_lte_less(self):
        check_is(version_lte("14.5", "14.6"), True)

    def test_lte_greater(self):
        check_is(version_lte("14.7", "14.6"), False)

    def test_lte_major_difference(self):
        check_is(version_lte("13.5", "14.6"), True)
        check_is(version_lte("15.0", "14.6"), False)

    def test_lte_different_length(self):
        check_is(version_lte("14", "14.6"), True)
        check_is(version_lte("15", "14.6"), False)
        check_is(version_lte("14.6", "15"), True)

    def test_lt_equal_returns_false(self):
        check_is(version_lt("14.6", "14.6"), False)

    def test_lt_less_returns_true(self):
        check_is(version_lt("14.5", "14.6"), True)

    def test_lt_greater_returns_false(self):
        check_is(version_lt("15.0", "14.6"), False)

    def test_lt_three_part_versions(self):
        check_is(version_lt("13.5.1", "13.5.2"), True)
        check_is(version_lt("13.5.2", "13.5.2"), False)

    def test_lte_padding_with_zeros(self):
        # "14" should be treated as "14.0" when compared to "14.0"
        check_is(version_lte("14", "14.0"), True)
        check_is(version_lte("14.0", "14"), True)


# ── Apple-style version extraction ───────────────────────────────────────────


class TestExtractMacosMaxVersion:
    def test_standard_pattern(self):
        check_equal(extract_macos_max_version("macOS 14.6 and earlier"), "14.6")

    def test_three_part_version(self):
        check_equal(extract_macos_max_version("macOS 15.1 and earlier"), "15.1")

    def test_multi_platform(self):
        # Should extract the macOS version, ignoring iOS
        check_equal(
            extract_macos_max_version("macOS 15 and earlier, iOS 18 and earlier"),
            "15",
        )

    def test_multi_platform_with_patches(self):
        check_equal(
            extract_macos_max_version("macOS 13.5 and earlier, iOS 16.6 and earlier"),
            "13.5",
        )

    def test_no_macos_pattern(self):
        check_is_none(extract_macos_max_version("Electron < 27.1.0"))

    def test_windows_only(self):
        check_is_none(
            extract_macos_max_version(
                "Windows Server 2012-2022, affects AD-bound macOS"
            )
        )

    def test_case_insensitive(self):
        check_equal(extract_macos_max_version("MACOS 14.6 AND EARLIER"), "14.6")


class TestExtractAppMaxVersion:
    def test_less_than_pattern(self):
        check_equal(extract_app_max_version("Electron < 27.1.0"), "27.1.0")

    def test_less_than_no_space(self):
        check_equal(extract_app_max_version("< 4.5.0"), "4.5.0")

    def test_no_pattern(self):
        check_is_none(extract_app_max_version("macOS 14.6 and earlier"))


class TestExtractPatchedMacosVersion:
    def test_simple(self):
        check_equal(extract_patched_macos_version("macOS 14.7"), "14.7")

    def test_multi_platform(self):
        check_equal(extract_patched_macos_version("macOS 13.5.2, iOS 16.6.1"), "13.5.2")

    def test_none_input(self):
        check_is_none(extract_patched_macos_version(None))

    def test_non_macos(self):
        check_is_none(extract_patched_macos_version("Electron 27.1.0"))


# ── is_affected logic ────────────────────────────────────────────────────────


class TestIsAffected:
    def test_none_version_assumes_affected(self):
        """No app version data → conservative: assume affected."""
        check_affected(
            True,
            app_version=None,
            affected_versions="macOS 14.6 and earlier",
            patched_version="macOS 15",
        )

    def test_safari_17_affected_by_hm_surf(self):
        """Safari 17.0 on macOS 14.5 IS affected by CVE-2024-44133.

        HM Surf is a macOS-level CVE - the version ceiling refers to
        macOS version, not Safari version. The matching should check
        against the host's macOS version.
        """
        check_affected(
            True,
            app_version="17.0",
            affected_versions="macOS 14.6 and earlier",
            patched_version="macOS 15",
            is_macos_cve=True,
            macos_version="14.5",
        )

    def test_safari_18_not_affected_by_hm_surf(self):
        """Safari 18.0 on macOS 15.0 IS NOT affected by CVE-2024-44133."""
        check_affected(
            False,
            app_version="18.0",
            affected_versions="macOS 14.6 and earlier",
            patched_version="macOS 15",
            is_macos_cve=True,
            macos_version="15.0",
        )

    def test_multi_platform_string(self):
        """Multi-platform string: macOS version should be extracted correctly."""
        check_affected(
            True,
            app_version="14.0",
            affected_versions="macOS 15 and earlier, iOS 18 and earlier",
            patched_version="macOS 15.1",
        )

    def test_version_above_multi_platform(self):
        check_affected(
            False,
            app_version="16.0",
            affected_versions="macOS 15 and earlier, iOS 18 and earlier",
            patched_version="macOS 15.1",
        )

    def test_electron_below_threshold(self):
        """Electron app below patched version IS affected."""
        check_affected(
            True,
            app_version="26.0.0",
            affected_versions="Electron < 27.1.0",
            patched_version="Electron 27.1.0",
        )

    def test_electron_at_patched_version(self):
        """Electron app at patched version IS NOT affected (< not <=)."""
        check_affected(
            False,
            app_version="27.1.0",
            affected_versions="Electron < 27.1.0",
            patched_version="Electron 27.1.0",
        )

    def test_inclusive_threshold_at_ceiling_is_affected(self):
        check_affected(
            True,
            app_version="27.1.0",
            affected_versions="Electron <= 27.1.0",
            patched_version="Electron 27.1.1",
        )

    def test_dashed_prerelease_below_patched_version_is_affected(self):
        check_affected(
            True,
            app_version="1.0.0-beta",
            affected_versions="TestApp < 1.0.0",
            patched_version="TestApp 1.0.0",
        )

    def test_final_release_at_patched_version_is_not_affected(self):
        check_affected(
            False,
            app_version="1.0.0",
            affected_versions="TestApp < 1.0.0",
            patched_version="TestApp 1.0.0",
        )

    def test_electron_above_patched_version(self):
        check_affected(
            False,
            app_version="28.0.0",
            affected_versions="Electron < 27.1.0",
            patched_version="Electron 27.1.0",
        )

    def test_macos_cve_with_host_version(self):
        """macOS-level CVE should check against host macOS version."""
        check_affected(
            True,
            app_version=None,
            affected_versions="macOS 14.6 and earlier",
            patched_version="macOS 14.7",
            is_macos_cve=True,
            macos_version="14.5",
        )

    def test_macos_cve_patched_host(self):
        """Host with patched macOS version should NOT be affected."""
        check_affected(
            False,
            app_version=None,
            affected_versions="macOS 14.6 and earlier",
            patched_version="macOS 14.7",
            is_macos_cve=True,
            macos_version="15.0",
        )

    def test_macos_cve_no_host_version(self):
        """No macOS version info → conservative: assume affected."""
        check_affected(
            True,
            app_version=None,
            affected_versions="macOS 14.6 and earlier",
            patched_version="macOS 14.7",
            is_macos_cve=True,
            macos_version=None,
        )

    def test_unparseable_affected_versions(self):
        """Unparseable string → conservative: assume affected."""
        check_affected(
            True,
            app_version="1.0",
            affected_versions="some unparseable string",
            patched_version=None,
        )

    def test_boundary_version_equal_to_ceiling(self):
        """Version exactly at ceiling is affected (lte, not lt)."""
        check_affected(
            True,
            app_version="14.6",
            affected_versions="macOS 14.6 and earlier",
            patched_version="macOS 14.7",
        )

    def test_boundary_version_one_above_ceiling(self):
        """Version one step above ceiling is NOT affected."""
        check_affected(
            False,
            app_version="14.7",
            affected_versions="macOS 14.6 and earlier",
            patched_version="macOS 14.7",
        )

    def test_patched_version_fallback(self):
        """When affected_versions has no parseable pattern, fall back to patched_version."""
        check_affected(
            True,
            app_version="14.6",
            affected_versions="multiple platforms affected",
            patched_version="macOS 14.7",
        )

        check_affected(
            False,
            app_version="14.7",
            affected_versions="multiple platforms affected",
            patched_version="macOS 14.7",
        )

    def test_macos_cve_patched_fallback(self):
        """macOS CVE uses patched_version when affected_versions is not parseable."""
        check_affected(
            True,
            app_version=None,
            affected_versions="Windows Server 2012-2022, affects AD-bound macOS",
            patched_version="macOS 15.0",
            is_macos_cve=True,
            macos_version="14.5",
        )

        check_affected(
            False,
            app_version=None,
            affected_versions="Windows Server 2012-2022, affects AD-bound macOS",
            patched_version="macOS 15.0",
            is_macos_cve=True,
            macos_version="15.0",
        )


# ── Integration with CveEntry ────────────────────────────────────────────────


class TestCveEntryIntegration:
    """Test is_affected against real CVE registry data patterns."""

    def test_cve_2024_44133_safari_affected(self):
        """CVE-2024-44133 (HM Surf): Safari 17.x on macOS 14.6 IS affected."""
        check_affected(
            True,
            app_version="17.0",
            affected_versions="macOS 14.6 and earlier",
            patched_version="macOS 15",
            is_macos_cve=True,
            macos_version="14.6",
        )

    def test_cve_2024_44133_safari_not_affected(self):
        """CVE-2024-44133 (HM Surf): Safari 18.x on macOS 15 IS NOT affected."""
        check_affected(
            False,
            app_version="18.0",
            affected_versions="macOS 14.6 and earlier",
            patched_version="macOS 15",
            is_macos_cve=True,
            macos_version="15.0",
        )

    def test_cve_2024_44131_files_app(self):
        """CVE-2024-44131: Files.app (Finder) on macOS 15 IS affected."""
        check_affected(
            True,
            app_version="15.0",
            affected_versions="macOS 15 and earlier, iOS 18 and earlier",
            patched_version="macOS 15.1",
        )

    def test_cve_2024_44131_files_app_patched(self):
        """CVE-2024-44131: Finder on macOS 15.1 IS NOT affected."""
        check_affected(
            False,
            app_version="15.1",
            affected_versions="macOS 15 and earlier, iOS 18 and earlier",
            patched_version="macOS 15.1",
        )

    def test_cve_2023_44402_electron(self):
        """CVE-2023-44402: Electron < 27.1.0 IS affected."""
        check_affected(
            True,
            app_version="26.4.0",
            affected_versions="Electron < 27.1.0",
            patched_version="Electron 27.1.0",
        )

    def test_cve_2023_44402_electron_patched(self):
        """CVE-2023-44402: Electron 27.1.0+ IS NOT affected."""
        check_affected(
            False,
            app_version="27.1.0",
            affected_versions="Electron < 27.1.0",
            patched_version="Electron 27.1.0",
        )
