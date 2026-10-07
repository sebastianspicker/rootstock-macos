"""Modeled FDA exposure comparison for scan posture diffs."""

from __future__ import annotations

from ..constants import FDA_SERVICE
from ..models import ScanResult
from .diff_models import FDAExposureDiff


def _fda_exposed_apps(scan: ScanResult) -> dict[str, dict]:
    """Map bundle_id to a row for apps that are both injectable and FDA-granted."""
    fda_clients = {g.client for g in scan.tcc_grants if g.service == FDA_SERVICE and g.allowed}
    return {
        app.bundle_id: {
            "bundle_id": app.bundle_id,
            "name": app.name,
            "methods": list(app.injection_methods),
        }
        for app in scan.applications
        if app.injection_methods and app.bundle_id in fda_clients
    }


def diff_fda_exposure(before: ScanResult, after: ScanResult) -> FDAExposureDiff:
    """Compare the sets of apps modeled as injectable AND holding Full Disk Access.

    This is a comparison of modeled exposure (an injectable app with an allowed FDA
    grant is a candidate path to FDA), not a graph shortest-path computation.
    """
    before_exposed = _fda_exposed_apps(before)
    after_exposed = _fda_exposed_apps(after)
    return FDAExposureDiff(
        new_exposure=[
            after_exposed[bid] for bid in sorted(set(after_exposed) - set(before_exposed))
        ],
        closed_exposure=[
            before_exposed[bid] for bid in sorted(set(before_exposed) - set(after_exposed))
        ],
    )
