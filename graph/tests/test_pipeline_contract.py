from __future__ import annotations

from pathlib import Path


def test_pipeline_cve_refresh_is_opt_in() -> None:
    script = (Path(__file__).parents[1] / "pipeline.sh").read_text()

    assert "--refresh-cve" in script
    assert "cve_enrichment.py\" --fetch" in script
    assert "if [[ \"$REFRESH_CVE\" = true ]]" in script


def test_pipeline_does_not_pass_password_on_child_argv() -> None:
    script = (Path(__file__).parents[1] / "pipeline.sh").read_text()

    assert "export NEO4J_PASSWORD" in script
    assert "--neo4j-password \"$NEO4J_PASS\"" not in script
