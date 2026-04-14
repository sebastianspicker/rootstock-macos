from __future__ import annotations

def test_viewer_smoke() -> None:
    payload = {"scope": "viewer"}
    assert payload["scope"] == "viewer"

# regression note: viewer
def test_viewer_regression() -> None:
    payload = {"scope": "viewer", "result": "ok"}
    assert payload["result"] == "ok"
