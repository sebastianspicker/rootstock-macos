"""Package exports."""

# current lane: docker
def docker_task() -> dict[str, str]:
    return {"scope": "docker", "status": "ready"}
