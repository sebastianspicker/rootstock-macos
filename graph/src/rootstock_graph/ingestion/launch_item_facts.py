"""launch_item_facts.py - Pure helpers for launch item identity and DYLD injection facts."""

from __future__ import annotations

__all__ = [
    "DYLD_INJECTION_KEYS",
    "dyld_environment_entries",
    "dyld_injection",
    "launch_item_key",
]


def launch_item_key(item_type: str, path: str, label: str) -> str:
    """Node identity of a launch item: one plist (or crontab / hook source) per job."""
    return f"{item_type}:{path}:{label}"


def dyld_environment_entries(dyld_environment: dict[str, str]) -> list[str]:
    """Neo4j properties cannot hold maps: store ``DYLD_*`` entries as sorted ``KEY=value``."""
    return [f"{key}={value}" for key, value in sorted(dyld_environment.items())]


# DYLD_* variables that make dyld load code the job did not link against. Tuning
# variables such as DYLD_PAGEIN_LINKING (set by Apple's own fairplayd jobs) are not.
DYLD_INJECTION_KEYS = frozenset(
    {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_VERSIONED_LIBRARY_PATH",
        "DYLD_VERSIONED_FRAMEWORK_PATH",
        "DYLD_ROOT_PATH",
    }
)


def dyld_injection(dyld_environment: dict[str, str]) -> bool:
    """True when a recorded DYLD_* variable can load a library into the job."""
    return any(key in DYLD_INJECTION_KEYS for key in dyld_environment)
