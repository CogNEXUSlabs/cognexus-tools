"""One header policy for every outbound SDK request (cloud, CLI and GUI).

``artzain.cloud._sdk_headers`` is the only place that knows the browser-like
header set the CDN/WAF currently requires; ``COGNEXUS_SDK_BROWSER_HEADERS``
selects it (``"1"``, the default for now) or the honest
``artzain-python-sdk/<ver>`` identity (``"0"``).
"""

from __future__ import annotations

import email.message
import io
import re
import urllib.request
from pathlib import Path

import pytest

import artzain.cli as cli
import artzain.cloud as cloud
import artzain.gui as gui

_ENV = "COGNEXUS_SDK_BROWSER_HEADERS"
_URL = "https://app.example.test/api/auth/token"
_BROWSER_ONLY = ("Origin", "Referer", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_ENV, raising=False)
    monkeypatch.delenv("COGNEXUS_CLI_USER_AGENT", raising=False)


def test_sdk_headers_honest_when_env_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_ENV, "0")
    h = cloud._sdk_headers(url=_URL)
    assert h["User-Agent"].startswith("artzain-python-sdk/")
    assert "Mozilla" not in h["User-Agent"]
    assert h["Accept"] == "application/json"
    for key in _BROWSER_ONLY:
        assert key not in h


def test_sdk_headers_browser_like_when_env_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_ENV, "1")
    h = cloud._sdk_headers(url=_URL)
    assert "Mozilla" in h["User-Agent"] and "Chrome" in h["User-Agent"]
    assert h["Origin"] == "https://app.example.test"
    assert h["Referer"] == "https://app.example.test/"
    assert h["Sec-Fetch-Site"] == "same-origin"
    assert h["Sec-Fetch-Mode"] == "cors"
    assert h["Sec-Fetch-Dest"] == "empty"


def test_sdk_headers_default_is_honest(monkeypatch: pytest.MonkeyPatch) -> None:
    # Since 0.6.11 the CDN allowlists ``artzain-python-sdk/`` on /api/*, so the
    # default is the honest identity (runbook, "CDN / WAF allowlist").
    monkeypatch.delenv(_ENV, raising=False)
    assert cloud._browser_headers_enabled() is False
    h = cloud._sdk_headers(url=_URL)
    assert h["User-Agent"].startswith("artzain-python-sdk/")
    assert "Sec-Fetch-Site" not in h


def test_sdk_headers_explicit_argument_beats_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_ENV, "1")
    assert "Sec-Fetch-Site" not in cloud._sdk_headers(url=_URL, browser_like=False)
    monkeypatch.setenv(_ENV, "0")
    assert cloud._sdk_headers(url=_URL, browser_like=True)["Sec-Fetch-Site"] == "same-origin"


def test_sdk_headers_browser_like_without_url_sends_no_fetch_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_ENV, "1")
    h = cloud._sdk_headers()
    assert "Mozilla" in h["User-Agent"]
    for key in _BROWSER_ONLY:
        assert key not in h


def test_sdk_headers_cli_user_agent_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_ENV, "1")
    monkeypatch.setenv("COGNEXUS_CLI_USER_AGENT", "my-edge-ua/1")
    assert cloud._sdk_headers(url=_URL)["User-Agent"] == "my-edge-ua/1"


def test_sdk_headers_browser_user_agent_only_in_browser_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_ENV, "1")
    assert cloud._sdk_headers(url=_URL, browser_user_agent="RealBrowser/9")["User-Agent"] == "RealBrowser/9"
    monkeypatch.setenv(_ENV, "0")
    ua = cloud._sdk_headers(url=_URL, browser_user_agent="RealBrowser/9")["User-Agent"]
    assert ua.startswith("artzain-python-sdk/")


def test_cloud_api_request_headers_stay_honest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_ENV, "1")
    h = cloud._api_request_headers("k")
    assert h["User-Agent"].startswith("artzain-python-sdk/")
    assert h["X-Api-Key"] == "k"
    assert "Sec-Fetch-Site" not in h


# ── CLI / GUI request builders go through _sdk_headers ──────────────────────


def _patch_sdk_headers(monkeypatch: pytest.MonkeyPatch, module) -> list[dict]:
    calls: list[dict] = []

    def fake(**kwargs):
        calls.append(kwargs)
        return {"X-Marker": "from-sdk-headers", "User-Agent": "marker-ua/0"}

    monkeypatch.setattr(module, "_sdk_headers", fake)
    return calls


def test_cli_request_headers_use_sdk_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_sdk_headers(monkeypatch, cli)
    h = cli._request_headers_for_url(_URL)
    assert calls == [{"url": _URL}]
    assert h["X-Marker"] == "from-sdk-headers"
    assert h["User-Agent"] == "marker-ua/0"
    assert h["X-Cognexus-Client"] == f"artzain-cli/{cli.__version__}"


class _FakeResp:
    status = 200
    headers: dict[str, str] = {}

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, n: int = -1) -> bytes:
        body, self._body = self._body, b""
        return body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_gui_bootstrap_uses_sdk_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_sdk_headers(monkeypatch, gui)
    seen: list[urllib.request.Request] = []

    def fake_urlopen(req, timeout=None):
        seen.append(req)
        return _FakeResp(b'{"token": "t", "email": "e", "display_name": "d"}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    out = gui._try_bootstrap("https://up.example.test/", "key-123")
    assert out == {"token": "t", "email": "e", "display_name": "d"}
    assert calls == [{"url": "https://up.example.test"}]
    req = seen[0]
    assert req.get_header("X-marker") == "from-sdk-headers"
    assert req.get_header("User-agent") == "marker-ua/0"
    assert req.get_header("X-api-key") == "key-123"


def test_gui_proxy_uses_sdk_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_sdk_headers(monkeypatch, gui)
    seen: list[urllib.request.Request] = []

    def fake_urlopen(req, timeout=None):
        seen.append(req)
        return _FakeResp(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    handler_cls = gui._make_handler("https://up.example.test", b"", "")
    h = handler_cls.__new__(handler_cls)
    h.path = "/api/conversations"
    h.headers = email.message.Message()
    h.headers["User-Agent"] = "RealBrowser/9"
    h.headers["Authorization"] = "Bearer jwt"
    h.wfile = io.BytesIO()
    for name in ("send_response", "send_header", "end_headers"):
        monkeypatch.setattr(h, name, lambda *a, **k: None, raising=False)

    h._proxy("GET")

    assert calls == [{"url": "https://up.example.test", "browser_user_agent": "RealBrowser/9"}]
    req = seen[0]
    assert req.full_url == "https://up.example.test/api/conversations"
    assert req.get_header("X-marker") == "from-sdk-headers"
    assert req.get_header("User-agent") == "marker-ua/0"
    assert req.get_header("Authorization") == "Bearer jwt"


def test_no_user_agent_literal_outside_cloud() -> None:
    src_dir = Path(cloud.__file__).parent
    for name in ("cli.py", "gui.py"):
        text = (src_dir / name).read_text(encoding="utf-8")
        assert "Mozilla/" not in text, name
        assert "_DEFAULT_BROWSER_UA" not in text, name
        assert "Sec-Fetch" not in text, name
        assert re.search(r'["\']User-Agent["\']\s*:', text) is None, name
