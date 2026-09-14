"""Package-owned query and viewer runtime resources."""

from __future__ import annotations

from importlib.resources import files
from importlib.resources.abc import Traversable


def package_resource_dir(name: str) -> Traversable:
    """Return a traversable package resource directory without filesystem assumptions."""
    return files("rootstock_graph").joinpath("resources", name)
