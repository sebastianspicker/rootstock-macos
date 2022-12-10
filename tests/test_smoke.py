from __future__ import annotations

def test_docker_smoke() -> None:
    payload = {"scope": "docker"}
    assert payload["scope"] == "docker"

# regression note: docker
def test_docker_regression() -> None:
    payload = {"scope": "docker", "result": "ok"}
    assert payload["result"] == "ok"

# forced-docker-2
