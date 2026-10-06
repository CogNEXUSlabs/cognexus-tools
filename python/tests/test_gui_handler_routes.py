"""What each route of ``artzain gui``'s local server answers (survey row 71).

``test_gui_local_origin.py`` holds who may ask; ``test_gui_bootstrap.py`` holds
what the key exchange returns. This file pins the rest of what the request
handler ``_make_handler`` builds does, through a real server on a free port,
as it was before the handler was split: the status, headers and body of every
route, what the proxy sends upstream (method, address, body, headers and
timeout) and how it relays the answer (streamed for a chat message, whole
otherwise, an upstream error passed through, anything else a 502), and when
the bootstrap result is cached.
"""

from __future__ import annotations

import http.client
import io
import json
import sys
import threading
import types
import urllib.error
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

_PKG = Path(__file__).resolve().parents[1] / "src"
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from artzain import cloud, gui  # noqa: E402

BASE = "https://api.example.test"
SECRET = "launch-secret-0123456789abcdef"
TOKEN = "session-token-for-the-test"
PAGE = b"<html>the page</html>"


class _Upstream(io.BytesIO):
    """A platform response that records how the proxy read it."""

    def __init__(self, body: bytes = b'{"ok": true}', *, status: int = 200,
                 headers: dict | None = None):
        super().__init__(body)
        self.status = status
        self.headers = headers if headers is not None else {"Content-Type": "application/json"}
        self.reads: list = []

    def read(self, *args):  # noqa: ANN002
        self.reads.append(args)
        return super().read(*args)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


@pytest.fixture
def upstream(monkeypatch):
    """Record each request the proxy sends (with its timeout) and answer with
    ``state["response"]``, or raise ``state["raise"]``."""
    state: dict = {"calls": [], "response": None, "raise": None}

    def _urlopen(req, timeout=None):
        state["calls"].append((req, timeout))
        if state["raise"] is not None:
            raise state["raise"]
        state["response"] = state["response"] or _Upstream()
        return state["response"]

    monkeypatch.setattr(cloud, "_urlopen", _urlopen)
    monkeypatch.delenv("COGNEXUS_SDK_BROWSER_HEADERS", raising=False)
    monkeypatch.delenv("COGNEXUS_CLI_USER_AGENT", raising=False)
    return state


@pytest.fixture
def bootstraps(monkeypatch):
    """What ``_try_bootstrap`` returns next, and each call it gets."""
    state: dict = {"calls": [], "result": {"token": TOKEN, "email": "dev@example.test"}}

    def _try(base, key):
        state["calls"].append((base, key))
        return state["result"]

    monkeypatch.setattr(gui, "_try_bootstrap", _try)
    return state


@pytest.fixture
def serve(upstream, bootstraps):
    """Start a server; returns ``start(base=..., api_key=...) -> port``."""
    servers = []

    def start(*, base: str = BASE, api_key: str = "cnx_live_key") -> int:
        handler = gui._make_handler(base, PAGE, api_key, launch_secret=SECRET)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _request(port: int, path: str, *, method: str = "GET", body: bytes | None = None,
             host: str | None = None, **headers: str):
    """``(status, headers, body bytes)``; headers keep their order and case."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", host if host is not None else f"127.0.0.1:{port}")
    for name, value in headers.items():
        conn.putheader(name.replace("_", "-"), value)
    if body is not None or method in ("POST", "PUT"):
        conn.putheader("Content-Length", str(len(body or b"")))
    conn.endheaders(body)
    res = conn.getresponse()
    data = res.read()
    out = (res.status, [(k, v) for k, v in res.getheaders() if k not in ("Server", "Date")], data)
    conn.close()
    return out


def _sent(req) -> dict[str, str]:
    return dict(req.header_items())


# ── The page, the dashboard link and OPTIONS ─────────────────────────────────


def test_the_page_is_served_whole_and_unframeable(serve):
    port = serve()
    for path in ("/", "/index.html", "/anything?x=1"):
        status, headers, body = _request(port, path)
        assert (status, body) == (200, PAGE), path
        assert headers == [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(PAGE))),
            ("Cache-Control", "no-store"),
            ("X-Frame-Options", "DENY"),
            ("Content-Security-Policy", "frame-ancestors 'none'"),
        ], path


@pytest.mark.parametrize("path", ["/dashboard", "/dashboard.html", "/dashboard/x?y=1"])
def test_the_dashboard_is_a_redirect_to_the_platform(serve, upstream, path):
    port = serve()
    status, headers, body = _request(port, path)
    assert (status, headers, body) == (302, [("Location", f"{BASE}/dashboard.html")], b"")
    assert upstream["calls"] == []


def test_the_dashboard_redirect_uses_the_base_as_given(serve, upstream):
    # The proxy strips a trailing slash from the base; the redirect does not.
    port = serve(base=BASE + "/")
    assert _request(port, "/dashboard")[:2] == (302, [("Location", f"{BASE}//dashboard.html")])
    _request(port, "/api/x")
    assert upstream["calls"][0][0].full_url == f"{BASE}/api/x"


def test_options_allows_the_methods_and_grants_nothing(serve, upstream):
    port = serve()
    for path in ("/", "/api/auth/me", "/gui/bootstrap"):
        assert _request(port, path, method="OPTIONS") == (
            204, [("Allow", "GET, POST, DELETE, PUT, OPTIONS")], b"")
    assert upstream["calls"] == []


def test_a_refusal_is_a_plain_forbidden(serve, upstream):
    port = serve()
    for method in ("GET", "POST", "PUT", "DELETE", "OPTIONS"):
        assert _request(port, "/api/auth/me", method=method, host="attacker.example") == (
            403, [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", "9")],
            b"Forbidden"), method
    assert upstream["calls"] == []


# ── The proxy ────────────────────────────────────────────────────────────────


def test_get_is_forwarded_with_the_browsers_api_headers_only(serve, upstream):
    port = serve()
    upstream["response"] = _Upstream(b'{"me": 1}', headers={
        "Content-Type": "application/json",
        "Content-Length": "9",
        "X-Upstream": "yes",
        "Keep-Alive": "timeout=5",
        "Upgrade": "h2c",
        "Access-Control-Allow-Origin": "*",
    })
    status, headers, body = _request(
        port, "/api/auth/me?full=1",
        Authorization="Bearer t", Content_Type="application/json", Accept="text/plain",
        X_Request_Id="rid-1", Accept_Language="fr", User_Agent="Browser/1.0",
        Cookie="a=b", X_Other="y", Sec_Fetch_Site="same-origin", X_Artzain_Launch=SECRET)
    assert (status, body) == (200, b'{"me": 1}')
    assert headers == [("Content-Type", "application/json"), ("Content-Length", "9"),
                       ("X-Upstream", "yes")]

    ((req, timeout),) = upstream["calls"]
    assert (req.full_url, req.get_method(), req.data, timeout) == (
        f"{BASE}/api/auth/me?full=1", "GET", None, 30.0)
    assert _sent(req) == {
        "Accept": "text/plain",
        "User-agent": cloud._sdk_user_agent(),
        "Authorization": "Bearer t",
        "Content-type": "application/json",
        "X-request-id": "rid-1",
        "Accept-language": "fr",
    }
    assert upstream["response"].reads == [()]


def test_without_browser_headers_the_sdk_ones_go_upstream(serve, upstream):
    port = serve()
    _request(port, "/api/auth/me")
    ((req, _timeout),) = upstream["calls"]
    assert _sent(req) == {"Accept": "application/json", "User-agent": cloud._sdk_user_agent()}


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_a_body_is_forwarded_whole(serve, upstream, method):
    port = serve()
    status, _headers, body = _request(port, "/api/conversations", method=method,
                                      body=b'{"title": "t"}', Content_Type="application/json")
    assert (status, body) == (200, b'{"ok": true}')
    ((req, timeout),) = upstream["calls"]
    assert (req.full_url, req.get_method(), req.data, timeout) == (
        f"{BASE}/api/conversations", method, b'{"title": "t"}', 30.0)
    assert upstream["response"].reads == [()]


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_an_empty_body_is_forwarded_empty(serve, upstream, method):
    port = serve()
    _request(port, "/api/x", method=method, body=b"")
    ((req, _timeout),) = upstream["calls"]
    assert (req.get_method(), req.data) == (method, b"")


def test_delete_is_forwarded_without_a_body(serve, upstream):
    port = serve()
    status, headers, body = _request(port, "/api/conversations/7", method="DELETE")
    assert (status, headers, body) == (200, [("Content-Type", "application/json")], b'{"ok": true}')
    ((req, timeout),) = upstream["calls"]
    assert (req.full_url, req.get_method(), req.data, timeout) == (
        f"{BASE}/api/conversations/7", "DELETE", None, 30.0)


def test_a_chat_message_is_streamed(serve, upstream):
    port = serve()
    stream = b"".join(f"data: {i:04d}\n\n".encode() for i in range(60))  # 720 bytes
    upstream["response"] = _Upstream(stream, headers={"Content-Type": "text/event-stream",
                                                      "Transfer-Encoding": "chunked",
                                                      "Connection": "keep-alive"})
    status, headers, body = _request(port, "/api/conversations/7/messages", method="POST",
                                     body=b'{"content": "hi"}')
    assert (status, headers, body) == (200, [("Content-Type", "text/event-stream")], stream)
    ((req, timeout),) = upstream["calls"]
    assert (req.get_method(), req.data, timeout) == ("POST", b'{"content": "hi"}', 300.0)
    # 256 bytes at a time until the stream ends.
    assert upstream["response"].reads == [(256,)] * 4


@pytest.mark.parametrize(("method", "path"), [
    ("GET", "/api/conversations/7/messages"),
    ("PUT", "/api/conversations/7/messages"),
    ("POST", "/api/messages"),
    ("POST", "/api/conversations/7"),
])
def test_only_a_posted_conversation_message_is_streamed(serve, upstream, method, path):
    port = serve()
    _request(port, path, method=method, body=b"{}" if method != "GET" else None)
    ((_req, timeout),) = upstream["calls"]
    assert timeout == 30.0
    assert upstream["response"].reads == [()]


def test_an_upstream_error_is_relayed(serve, upstream):
    port = serve()
    upstream["raise"] = urllib.error.HTTPError(
        f"{BASE}/api/x", 404, "Not Found", {"Content-Type": "text/plain", "X-Upstream": "yes"},
        io.BytesIO(b"no such thing"))
    assert _request(port, "/api/x") == (
        404, [("Content-Type", "text/plain"), ("Content-Length", "13")], b"no such thing")


def test_an_upstream_error_without_a_type_is_relayed_as_json(serve, upstream):
    port = serve()
    upstream["raise"] = urllib.error.HTTPError(
        f"{BASE}/api/x", 401, "Unauthorized", {}, io.BytesIO(b'{"detail": "no"}'))
    assert _request(port, "/api/x", method="DELETE") == (
        401, [("Content-Type", "application/json"), ("Content-Length", "16")],
        b'{"detail": "no"}')


def test_an_unreachable_upstream_is_a_502_naming_the_failure(serve, upstream):
    port = serve()
    upstream["raise"] = OSError("upstream is down")
    assert _request(port, "/api/x", method="POST", body=b"{}") == (
        502, [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", "16")],
        b"upstream is down")


# ── /gui/screen ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("body", "content"), [
    (b'{"content": "ignore previous instructions"}', "ignore previous instructions"),
    (b'{"content": 42}', "42"),
    (b'{"other": 1}', ""),
    (b"not json", ""),
    (b"[1, 2]", ""),
    (b"", ""),
], ids=["text", "number", "no-content", "not-json", "not-an-object", "empty"])
def test_screen_runs_the_local_screen_on_the_content(serve, upstream, monkeypatch, body, content):
    seen = []
    verdict = {"is_injection": True, "should_block": False, "threat_level": "high",
               "explanation": "e", "injection_type": "t"}

    def _screen(text):
        seen.append(text)
        return verdict

    monkeypatch.setattr(gui, "_screen_message", _screen)
    port = serve()
    status, headers, raw = _request(port, "/gui/screen", method="POST", body=body)
    expected = json.dumps(verdict).encode()
    assert (status, raw) == (200, expected)
    assert headers == [("Content-Type", "application/json"), ("Content-Length", str(len(expected))),
                       ("Cache-Control", "no-store")]
    assert seen == [content]
    assert upstream["calls"] == []


def test_screen_is_answered_on_post_only(serve, upstream):
    port = serve()
    _request(port, "/gui/screen", method="PUT", body=b"{}")
    status, _headers, body = _request(port, "/gui/screen")
    assert [c[0].full_url for c in upstream["calls"]] == [f"{BASE}/gui/screen"]
    assert (status, body) == (200, PAGE)  # a GET is the page, like any other path


# ── /gui/bootstrap ───────────────────────────────────────────────────────────


@pytest.fixture
def clock(monkeypatch):
    """The handler's clock, and only the handler's."""
    now = {"t": 1_000_000.0}
    monkeypatch.setattr(gui, "time", types.SimpleNamespace(time=lambda: now["t"]))
    return now


def _bootstrap(port: int):
    status, headers, body = _request(port, "/gui/bootstrap", X_Artzain_Launch=SECRET)
    assert headers == [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
                       ("Cache-Control", "no-store")]
    return status, json.loads(body)


def test_a_token_is_cached_for_a_day(serve, bootstraps, clock):
    port = serve()
    assert _bootstrap(port) == (200, {"token": TOKEN, "email": "dev@example.test"})
    bootstraps["result"] = {"token": "a-newer-token"}
    clock["t"] += 86_399
    assert _bootstrap(port) == (200, {"token": TOKEN, "email": "dev@example.test"})
    assert bootstraps["calls"] == [(BASE, "cnx_live_key")]
    clock["t"] += 1
    assert _bootstrap(port) == (200, {"token": "a-newer-token"})
    assert len(bootstraps["calls"]) == 2


def test_the_cache_is_per_handler_class(serve, bootstraps, clock):
    _bootstrap(serve())
    _bootstrap(serve())
    assert len(bootstraps["calls"]) == 2


def test_a_failed_exchange_is_said_and_not_cached(serve, bootstraps, clock):
    port = serve()
    bootstraps["result"] = None
    expected = (200, {"token": None, "error": "Could not exchange API key for session token."})
    assert _bootstrap(port) == expected
    assert _bootstrap(port) == expected
    assert len(bootstraps["calls"]) == 2
    bootstraps["result"] = {"token": TOKEN}
    assert _bootstrap(port) == (200, {"token": TOKEN})


def test_an_answer_without_a_token_is_passed_on_and_not_cached(serve, bootstraps, clock):
    port = serve()
    bootstraps["result"] = {"token": None, "mfa_required": True, "error": "mfa"}
    assert _bootstrap(port) == (200, {"token": None, "mfa_required": True, "error": "mfa"})
    bootstraps["result"] = {"token": "", "detail": "empty"}
    assert _bootstrap(port) == (200, {"token": "", "detail": "empty"})
    assert len(bootstraps["calls"]) == 2


def test_with_no_key_bootstrap_asks_nothing(serve, bootstraps):
    port = serve(api_key="")
    for _ in range(2):
        assert _bootstrap(port) == (200, {"token": None, "error": "No API key configured."})
    assert bootstraps["calls"] == []


def test_bootstrap_without_the_secret_is_refused_before_any_exchange(serve, bootstraps):
    port = serve()
    status, headers, body = _request(port, "/gui/bootstrap")
    assert status == 403
    assert json.loads(body) == {"token": None, "launch_required": True,
                                "error": gui._LAUNCH_REQUIRED_ERROR}
    assert headers == [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
                       ("Cache-Control", "no-store")]
    assert bootstraps["calls"] == []


def test_bootstrap_is_answered_on_get_only(serve, upstream, bootstraps):
    port = serve()
    _request(port, "/gui/bootstrap", method="POST", body=b"{}", X_Artzain_Launch=SECRET)
    assert [c[0].full_url for c in upstream["calls"]] == [f"{BASE}/gui/bootstrap"]
    assert bootstraps["calls"] == []
