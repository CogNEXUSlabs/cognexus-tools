"""The local CLI asks the engine on 127.0.0.1, where the dashboard is published.

Survey row 40 binds the dashboard to 127.0.0.1. ``localhost`` can resolve to
``::1`` first, where every connection is then refused before IPv4 is tried
(two seconds a request on Windows), so the CLI's own requests name
127.0.0.1; the links it prints keep ``localhost``.
"""

from __future__ import annotations

import json

import pytest

from artzain import local


@pytest.fixture
def port(monkeypatch):
    monkeypatch.setattr(local, "ui_port", lambda: 9090)


def test_requests_name_127_0_0_1_and_links_keep_localhost(port):
    assert local.request_base_url() == "http://127.0.0.1:9090"
    assert local.base_url() == "http://localhost:9090"


def test_a_health_read_goes_to_127_0_0_1(port, monkeypatch):
    asked: list = []

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps({"status": "healthy"}).encode()

    def _open(url, timeout=None):
        asked.append(url if isinstance(url, str) else url.full_url)
        return _Resp()

    monkeypatch.setattr(local.urllib.request, "urlopen", _open)

    assert local.fetch_health() == {"status": "healthy"}
    assert asked == ["http://127.0.0.1:9090/health"]


def test_a_post_goes_to_127_0_0_1(port, monkeypatch):
    asked: list = []

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"{}"

    def _open(req, timeout=None):
        asked.append(req.full_url)
        return _Resp()

    monkeypatch.setattr(local.urllib.request, "urlopen", _open)

    local._api_post("/api/x", {})
    assert asked == ["http://127.0.0.1:9090/api/x"]
