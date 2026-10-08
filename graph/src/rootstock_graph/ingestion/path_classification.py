"""path_classification.py - Pure checks for programs that live where a normal user can write.

A launch item or process whose executable sits in a temporary directory, the shared
user folder or a user's home can be replaced by that user (or anything running as
them) without an administrator password, so the graph flags it at import time.

Paths are normalised first (``posixpath.normpath`` removes ``..``, ``.`` and doubled
slashes) and compared case-insensitively, as the default APFS volume is.
"""

from __future__ import annotations

import posixpath

__all__ = [
    "command_in_user_writable_location",
    "program_in_user_writable_location",
]

# Lower-case: paths are compared after ``_normalized``.
_SHARED_WRITABLE_PREFIXES = (
    "/tmp/",
    "/private/tmp/",
    "/var/tmp/",
    "/private/var/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "/users/shared/",
)

# Folders of a home directory that processes are commonly launched from after a
# download or drop; `~/Applications` is the per-user install location and excluded.
_PROCESS_HOME_FOLDERS = frozenset({"library", "downloads", "desktop", "documents"})


def _normalized(path: str) -> str:
    """``path`` without ``..``/``.``/doubled slashes, lower-cased for comparison."""
    return posixpath.normpath(path).lower()


def _home_folder(path: str) -> str | None:
    """First folder below ``/users/<name>/``; "" for a file directly in the home, None outside."""
    parts = path.split("/")
    if len(parts) < 4 or parts[0] != "" or parts[1] != "users" or parts[2] in {"", "shared"}:
        return None
    return parts[3] if len(parts) > 4 else ""


def _in_shared_writable_location(path: str) -> bool:
    return path.startswith(_SHARED_WRITABLE_PREFIXES)


def command_in_user_writable_location(command: str | None) -> bool:
    """True under a temp dir, /Users/Shared, or ~/Library, ~/Downloads, ~/Desktop, ~/Documents."""
    if not command:
        return False
    path = _normalized(command)
    return _in_shared_writable_location(path) or _home_folder(path) in _PROCESS_HOME_FOLDERS


def program_in_user_writable_location(program: str | None) -> bool:
    """True under a temp dir, /Users/Shared, or anywhere in a home outside ~/Applications."""
    if not program:
        return False
    path = _normalized(program)
    if _in_shared_writable_location(path):
        return True
    folder = _home_folder(path)
    return folder is not None and folder != "applications"
