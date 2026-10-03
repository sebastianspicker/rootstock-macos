from __future__ import annotations

from types import SimpleNamespace

import pytest

from rootstock_graph.vulnerability import cve_enrichment


def test_fetch_and_cache_preserves_partial_nvd_errors(monkeypatch) -> None:
    monkeypatch.setattr(cve_enrichment, "fetch_epss", lambda force: {"CVE-1": {}})
    monkeypatch.setattr(cve_enrichment, "fetch_kev", lambda force: {"CVE-1": {}})

    def fetch_nvd(*, force: bool, errors: list[str]) -> dict:
        errors.append("NVD partial: 1/1 CVEs failed enrichment")
        return {"CVE-1": {"vector": None}}

    monkeypatch.setattr(cve_enrichment, "fetch_nvd", fetch_nvd)
    monkeypatch.setattr(cve_enrichment, "has_any_enrichment_cache", lambda: False)

    assert cve_enrichment.fetch_and_cache() == ["NVD partial: 1/1 CVEs failed enrichment"]


class _FakeResponse:
    def __init__(self, status_code: int, chunks: list[bytes]) -> None:
        self.status_code = status_code
        self.chunks = chunks
        self.iterated = False
        self.closed = False

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, *, chunk_size: int):
        del chunk_size
        self.iterated = True
        yield from self.chunks

    def close(self) -> None:
        self.closed = True


class _FakeSession:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response

    def prepare_request(self, request):
        return SimpleNamespace(url=request.url)

    def merge_environment_settings(self, *_args, **_kwargs):
        return {"verify": True, "cert": None, "proxies": {}}

    def get_adapter(self, _url):
        return self

    def send(self, _prepared, **kwargs):
        assert kwargs["stream"] is True
        return self.response

    def close(self) -> None:
        return None


def test_enrichment_redirect_is_rejected_without_reading_body(monkeypatch) -> None:
    response = _FakeResponse(302, [b'{"redirect": true}'])
    monkeypatch.setattr(cve_enrichment.requests, "Session", lambda: _FakeSession(response))

    with pytest.raises(RuntimeError, match="redirect"):
        cve_enrichment._fetch_json("https://example.test/feed")

    assert response.iterated is False
    assert response.closed is True


def test_enrichment_decoded_body_limit_is_enforced(monkeypatch) -> None:
    response = _FakeResponse(200, [b"a" * 8, b"b" * 8])
    monkeypatch.setattr(cve_enrichment, "MAX_ENRICHMENT_JSON_BYTES", 12)
    monkeypatch.setattr(cve_enrichment.requests, "Session", lambda: _FakeSession(response))

    with pytest.raises(RuntimeError, match="decoded size limit"):
        cve_enrichment._fetch_json("https://example.test/feed")

    assert response.closed is True
