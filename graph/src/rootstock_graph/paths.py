"""Package-owned query and viewer runtime resources."""

from __future__ import annotations

from importlib.resources import files

try:
    from importlib.resources.abc import Traversable
except ImportError:  # Python 3.10
    from importlib.abc import Traversable


def package_resource_dir(name: str) -> Traversable:
    """Return a traversable package resource directory without filesystem assumptions."""
    return files("rootstock_graph").joinpath("resources", name)
