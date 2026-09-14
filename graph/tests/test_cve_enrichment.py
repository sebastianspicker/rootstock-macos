from __future__ import annotations

from rootstock_graph.vulnerability import cve_enrichment


def test_fetch_and_cache_preserves_partial_nvd_errors(monkeypatch) -> None:
    monkeypatch.setattr(cve_enrichment, "fetch_epss", lambda force: {"CVE-1": {}})
    monkeypatch.setattr(cve_enrichment, "fetch_kev", lambda force: {"CVE-1": {}})

    def fetch_nvd(*, force: bool, errors: list[str]) -> dict:
        errors.append("NVD partial: 1/1 CVEs failed enrichment")
        return {"CVE-1": {"vector": None}}

    monkeypatch.setattr(cve_enrichment, "fetch_nvd", fetch_nvd)
    monkeypatch.setattr(cve_enrichment, "_has_any_enrichment_cache", lambda: False)

    assert cve_enrichment.fetch_and_cache() == ["NVD partial: 1/1 CVEs failed enrichment"]
