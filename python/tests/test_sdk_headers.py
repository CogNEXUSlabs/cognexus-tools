"""One header policy for every outbound SDK request (cloud, CLI and GUI).

``artzain.cloud._sdk_headers`` is the only place that chooses the headers an
outbound request carries: ``Accept`` and the identifiable
``artzain-python-sdk/<ver>`` User-Agent the CDN allowlists on ``/api/*``
(docs/runbooks/supply-chain.md, "CDN / WAF allowlist"). The browser-like set
the edge required before 5 Sep 2026 (a desktop-browser User-Agent,
``Origin``/``Referer`` and ``Sec-Fetch-*`` metadata) and the environment
switch that selected it were removed in 0.6.65; setting that variable has no
effect (open-items 9.55).
"""

from __future__ import annotations

import email.message
import inspect
import io
import re
import urllib.request
from pathlib import Path

import pytest

import artzain.cli as cli
import artzain.cloud as cloud
import artzain.gui as gui

_RETIRED_SWITCH = "COGNEXUS_SDK_BROWSER_HEADERS"
_BROWSER_ONLY = (
    "Origin", "Referer", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Accept-Language",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_RETIRED_SWITCH, raising=False)
    monkeypatch.delenv("COGNEXUS_CLI_USER_AGENT", raising=False)


def _assert_sdk_identity(h: dict[str, str]) -> None:
    assert h["User-Agent"] == f"artzain-python-sdk/{cloud._package_version()}"
    assert "Mozilla" not in h["User-Agent"]
    assert h["Accept"] == "application/json"
    for key in _BROWSER_ONLY:
        assert key not in h
    assert set(h) == {"User-Agent", "Accept"}


def test_sdk_headers_are_the_sdk_identity() -> None:
    _assert_sdk_identity(cloud._sdk_headers())


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_the_retired_switch_has_no_effect(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(_RETIRED_SWITCH, value)
    _assert_sdk_identity(cloud._sdk_headers())


def test_sdk_headers_take_no_arguments() -> None:
    # url, browser_like and browser_user_agent went with the browser-like
    # branch: nothing about the request changes the headers it carries.
    assert list(inspect.signature(cloud._sdk_headers).parameters) == []


def test_the_browser_like_branch_is_gone() -> None:
    for name in ("_browser_headers_enabled", "_BROWSER_HEADERS_ENV",
                 "_BROWSER_HEADERS_DEFAULT", "_BROWSER_LIKE_UA"):
        assert not hasattr(cloud, name), name
    src_dir = Path(cloud.__file__).parent
    for path in sorted(src_dir.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert _RETIRED_SWITCH not in text, path.name
        assert "Mozilla/" not in text, path.name


def test_sdk_headers_cli_user_agent_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COGNEXUS_CLI_USER_AGENT", "my-edge-ua/1")
    h = cloud._sdk_headers()
    assert h["User-Agent"] == "my-edge-ua/1"
    assert h["Accept"] == "application/json"


def test_a_blank_cli_user_agent_override_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COGNEXUS_CLI_USER_AGENT", "   ")
    assert cloud._sdk_headers()["User-Agent"].startswith("artzain-python-sdk/")


def test_cloud_api_request_headers_carry_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_RETIRED_SWITCH, "1")
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
    h = cli._request_headers()
    assert calls == [{}]
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

    monkeypatch.setattr(cloud, "_urlopen", fake_urlopen)
    out = gui._try_bootstrap("https://up.example.test/", "key-123")
    assert out == {"token": "t", "email": "e", "display_name": "d"}
    assert calls == [{}]
    req = seen[0]
    assert req.get_header("X-marker") == "from-sdk-headers"
    assert req.get_header("User-agent") == "marker-ua/0"
    assert req.get_header("X-api-key") == "key-123"


def test_gui_proxy_uses_sdk_headers_not_the_browsers(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_sdk_headers(monkeypatch, gui)
    seen: list[urllib.request.Request] = []

    def fake_urlopen(req, timeout=None):
        seen.append(req)
        return _FakeResp(b"{}")

    monkeypatch.setattr(cloud, "_urlopen", fake_urlopen)
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

    # The browser's own User-Agent was forwarded while the edge required a
    # browser; the proxy identifies as the SDK now, like every other call.
    assert calls == [{}]
    req = seen[0]
    assert req.full_url == "https://up.example.test/api/conversations"
    assert req.get_header("X-marker") == "from-sdk-headers"
    assert req.get_header("User-agent") == "marker-ua/0"
    assert req.get_header("Authorization") == "Bearer jwt"


def test_no_user_agent_literal_outside_cloud() -> None:
    src_dir = Path(cloud.__file__).parent
    for name in ("cli.py", "gui.py"):
        text = (src_dir / name).read_text(encoding="utf-8")
        assert "_DEFAULT_BROWSER_UA" not in text, name
        # No Sec-Fetch-* header is set here (a dict key, send_header or
        # add_header, an item assignment): cloud._sdk_headers alone chooses
        # outbound headers. The GUI server reads the one a browser sends it,
        # to refuse other sites (survey 25 Sep 2026, row 34).
        assert re.search(r'["\']Sec-Fetch-[\w-]+["\']\s*(?::|,|\]\s*=)', text, re.IGNORECASE) is None, name
        assert re.search(r'["\']User-Agent["\']\s*:', text) is None, name
