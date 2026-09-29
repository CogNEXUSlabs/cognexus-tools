"""``artzain gui`` hands its session token only to the page it opened.

``/gui/bootstrap`` exchanges the configured API key for a dashboard session
token and hands it to the browser. It answered any request that reached the
local port: whatever its ``Host``, ``Origin`` or ``Sec-Fetch-Site``, and the
proxied API answered with ``Access-Control-Allow-Origin: *``. A page whose
name was made to resolve to the loopback address, or another local user,
could read the token.

Now every request must name this server (``127.0.0.1`` or ``localhost``), a
request another site sends is refused (a top-level navigation to the page
excepted: it holds no secret and cannot be framed), and the token is handed
over only with the per-launch secret that ``artzain gui`` puts in the fragment
of the address it opens and prints. The fragment never reaches a server, the
page the server sends to anyone does not hold the secret, and the browser is
opened through a private redirect file, so the secret is not on its command
line either.
"""

from __future__ import annotations

import http.client
import io
import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

_PKG = Path(__file__).resolve().parents[1] / "src"
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from artzain import cloud, gui  # noqa: E402

SECRET = "launch-secret-0123456789abcdef"
TOKEN = "session-token-for-the-test"
METHODS = ("GET", "POST", "PUT", "DELETE", "OPTIONS")


class _Upstream(io.BytesIO):
    """A platform response: the proxy tests never reach the network."""

    def __init__(self, body: bytes = b'{"ok": true}', headers: dict | None = None):
        super().__init__(body)
        self.status = 200
        self.headers = headers or {"Content-Type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


@pytest.fixture
def upstream(monkeypatch):
    """Record what the proxy sends upstream and answer with ``state["response"]``."""
    state = {"requests": [], "response": None}

    def _urlopen(req, timeout=None):
        state["requests"].append(req)
        return state["response"] or _Upstream()

    monkeypatch.setattr(cloud, "_urlopen", _urlopen)
    return state


@pytest.fixture
def serve(monkeypatch, upstream):
    """Start a GUI server on a free port; returns ``start(...) -> port``."""
    monkeypatch.setattr(gui, "_try_bootstrap",
                        lambda base, key: {"token": TOKEN, "email": "dev@example.test"})
    servers = []

    def start(*, legacy: bool = False, api_key: str = "cnx_live_key") -> int:
        srv = ThreadingHTTPServer(("127.0.0.1", 0), gui.BaseHTTPRequestHandler)
        if legacy:
            # The call shape existing callers use: no secret.
            srv.RequestHandlerClass = gui._make_handler("https://api.example.test",
                                                        b"<html>page</html>", api_key)
        else:
            srv.RequestHandlerClass = gui._make_handler("https://api.example.test",
                                                        b"<html>page</html>", api_key,
                                                        launch_secret=SECRET)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _request(port: int, path: str, *, host: str | None = None, method: str = "GET",
             body: bytes | None = None, **headers: str):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", host if host is not None else f"127.0.0.1:{port}")
    for name, value in headers.items():
        conn.putheader(name.replace("_", "-"), value)
    conn.putheader("Content-Length", str(len(body or b"")))
    conn.endheaders(body)
    res = conn.getresponse()
    text = res.read().decode("utf-8", "replace")
    out = (res.status, {k.lower(): v for k, v in res.getheaders()}, text)
    conn.close()
    return out


def _bootstrap(port: int, **kwargs):
    headers = {"X_Artzain_Launch": SECRET}
    headers.update(kwargs.pop("headers", {}))
    return _request(port, "/gui/bootstrap", **kwargs, **headers)


# ── What a rebinding page, another site or another local user gets ────────────

def test_the_old_call_shape_serves_no_token_to_a_rebinding_page(serve):
    port = serve(legacy=True)
    status, _headers, body = _request(port, "/gui/bootstrap", host=f"attacker.example:{port}")
    assert status == 403, body
    assert TOKEN not in body


def test_without_a_launch_secret_no_token_is_handed_out(serve):
    # The old call shape, from this server's own page: still no token.
    port = serve(legacy=True)
    status, _headers, body = _request(port, "/gui/bootstrap", X_Artzain_Launch="anything")
    assert status == 403, body
    assert TOKEN not in body


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("host", ["attacker.example:{port}", "localhost.attacker.example:{port}",
                                  "127.0.0.1.:{port}", "[::1]:{port}", "127.0.0.1:{port}x", ""])
def test_a_request_that_does_not_name_this_server_is_refused(serve, upstream, method, host):
    port = serve()
    for path in ("/gui/bootstrap", "/", "/api/auth/me"):
        status, _headers, body = _request(port, path, method=method, host=host.format(port=port),
                                          X_Artzain_Launch=SECRET)
        assert status == 403, (method, path, body)
        assert TOKEN not in body
    assert upstream["requests"] == []


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("headers", [
    {"Origin": "http://attacker.example"},
    {"Origin": "null"},
    {"Origin": "http://localhost:{port}"},           # not the Host this request names
    {"Sec_Fetch_Site": "cross-site"},
    {"Sec_Fetch_Site": "same-site"},
    {"Sec_Fetch_Site": "cross-site", "Sec_Fetch_Mode": "no-cors", "Sec_Fetch_Dest": "empty"},
], ids=["foreign-origin", "null-origin", "other-name-origin", "cross-site", "same-site", "cross-site-no-cors"])
def test_a_request_another_site_sends_is_refused(serve, upstream, method, headers):
    port = serve()
    headers = {k: v.format(port=port) for k, v in headers.items()}
    for path in ("/gui/bootstrap", "/", "/api/auth/me"):
        status, _h, body = _request(port, path, method=method, X_Artzain_Launch=SECRET, **headers)
        assert status == 403, (method, path, body)
        assert TOKEN not in body
    assert upstream["requests"] == []


@pytest.mark.parametrize("secret", [None, "", "wrong-secret", SECRET + "x", SECRET[:-1]],
                         ids=["missing", "empty", "wrong", "longer", "prefix"])
def test_the_token_needs_the_launch_secret(serve, secret):
    port = serve()
    headers = {} if secret is None else {"X_Artzain_Launch": secret}
    status, _h, body = _request(port, "/gui/bootstrap", **headers)
    assert status == 403, body
    assert TOKEN not in body
    assert json.loads(body)["launch_required"] is True


def test_with_no_api_key_the_page_is_told_so_rather_than_sent_for_the_address(serve):
    port = serve(api_key="")
    status, _h, body = _request(port, "/gui/bootstrap")
    assert status == 200, body
    assert json.loads(body) == {"token": None, "error": "No API key configured."}


# ── What the page the server opened gets ─────────────────────────────────────

@pytest.mark.parametrize("host", ["127.0.0.1:{port}", "localhost:{port}", "127.0.0.1", "localhost",
                                  "127.0.0.1:9999", "LOCALHOST:{port}"],
                         ids=["ipv4", "localhost", "default-port", "localhost-default-port", "forwarded", "upper-case"])
@pytest.mark.parametrize("fetch_site", [None, "same-origin", "none"])
def test_the_page_it_opened_gets_the_token(serve, host, fetch_site):
    port = serve()
    host = host.format(port=port)
    headers = {"Origin": f"http://{host}"} if fetch_site == "same-origin" else {}
    if fetch_site:
        headers["Sec_Fetch_Site"] = fetch_site
    status, _h, body = _bootstrap(port, host=host, headers=headers)
    assert status == 200, body
    assert json.loads(body)["token"] == TOKEN


@pytest.mark.parametrize("site", ["cross-site", "same-site"])
def test_a_link_to_the_page_from_another_site_opens_it_unframeable(serve, site):
    port = serve()
    nav = {"Sec_Fetch_Site": site, "Sec_Fetch_Mode": "navigate", "Sec_Fetch_Dest": "document"}
    status, headers, body = _request(port, "/", **nav)
    assert status == 200 and body == "<html>page</html>"
    assert headers["x-frame-options"] == "DENY"
    assert headers["content-security-policy"] == "frame-ancestors 'none'"
    # A navigation reaches the page only: never the token, never the API.
    for path in ("/gui/bootstrap", "/api/auth/me"):
        status, _h, body = _request(port, path, X_Artzain_Launch=SECRET, **nav)
        assert status == 403, (path, body)
        assert TOKEN not in body


def test_the_page_itself_is_served_without_the_secret(serve):
    port = serve()
    status, _h, body = _request(port, "/")
    assert status == 200 and body == "<html>page</html>"
    assert SECRET not in gui._GUI_HTML_TEMPLATE


# ── No cross-origin grants, and nothing of the browser's passed on ────────────

def test_no_response_grants_another_origin(serve, upstream):
    port = serve()
    upstream["response"] = _Upstream(headers={"Content-Type": "application/json",
                                              "Access-Control-Allow-Origin": "*",
                                              "Access-Control-Allow-Credentials": "true"})
    for method, path in (("OPTIONS", "/api/auth/me"), ("GET", "/api/auth/me"), ("GET", "/gui/bootstrap")):
        status, headers, _body = _request(port, path, method=method, X_Artzain_Launch=SECRET)
        assert status < 400, (method, path, status)
        assert not [k for k in headers if k.startswith("access-control-")], (method, path, headers)


def test_the_proxy_does_not_pass_on_the_browsers_origin_headers(serve, upstream):
    port = serve()
    status, _h, _body = _request(port, "/api/auth/me", Origin=f"http://127.0.0.1:{port}",
                                 Sec_Fetch_Site="same-origin", Authorization="Bearer t")
    assert status == 200
    (req,) = upstream["requests"]
    sent = {k.lower() for k in req.headers}
    assert "sec-fetch-site" not in sent and "x-artzain-launch" not in sent
    assert req.get_header("Authorization") == "Bearer t"


# ── The launcher ──────────────────────────────────────────────────────────────

def test_the_launch_address_carries_the_secret_in_its_fragment():
    assert gui._launch_url(4321, SECRET) == f"http://127.0.0.1:4321/#launch={SECRET}"
    secrets = {gui._new_launch_secret() for _ in range(3)}
    assert len(secrets) == 3 and all(len(s) >= 32 for s in secrets)


def test_the_redirect_file_is_private_and_leads_to_the_launch_address(tmp_path):
    url = gui._launch_url(4321, SECRET)
    path = gui._write_redirect_file(url)
    try:
        assert path is not None and SECRET not in str(path)
        page = path.read_text(encoding="utf-8")
        assert f'content="0;url={url}"' in page and f'href="{url}"' in page
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
            assert path.parent.stat().st_mode & 0o777 == 0o700
    finally:
        if path is not None:
            shutil.rmtree(path.parent, ignore_errors=True)


@pytest.fixture
def launch(monkeypatch, capsys):
    """Run ``launch_gui`` with a stand-in server and browser; returns ``run(**kw) -> record``."""
    real_make = gui._make_handler

    def run(**kwargs) -> dict:
        record: dict = {"opened": []}
        opened = threading.Event()

        def make(base, html_bytes, key, **kw):
            record["html"], record["kwargs"] = html_bytes, kw
            return real_make(base, html_bytes, key, **kw)

        def open_later(target):
            page = None
            if target.startswith("file:"):
                page = Path(urllib.request.url2pathname(target[len("file:"):])).read_text(encoding="utf-8")
            record["opened"].append((target, page))
            opened.set()

        class _Server:
            def __init__(self, address, handler):
                record["handler"] = handler

            def serve_forever(self):
                if not kwargs.get("no_browser"):
                    opened.wait(10)
                raise KeyboardInterrupt

            def shutdown(self):
                pass

        monkeypatch.setattr(gui, "_make_handler", make)
        monkeypatch.setattr(gui, "_open_browser_later", open_later)
        monkeypatch.setattr(gui, "ThreadingHTTPServer", _Server)
        gui.launch_gui("https://api.example.test", api_key="cnx_live_key", port=4321, **kwargs)
        record["printed"] = capsys.readouterr().out
        return record

    return run


def test_launch_hands_the_server_a_fresh_secret_and_the_browser_a_private_link(launch):
    first, second = launch(), launch()
    secret = first["kwargs"]["launch_secret"]
    assert secret and len(secret) >= 32 and secret != second["kwargs"]["launch_secret"]
    url = f"http://127.0.0.1:4321/#launch={secret}"
    assert url in first["printed"]
    assert secret.encode() not in first["html"]
    (target, page), = first["opened"]
    assert target.startswith("file:") and secret not in target
    assert f'url={url}"' in page
    # The redirect file is gone once the server stops.
    assert not Path(urllib.request.url2pathname(target[len("file:"):])).exists()


def test_launch_without_a_browser_prints_the_link_and_opens_nothing(launch):
    run = launch(no_browser=True)
    assert run["opened"] == []
    assert f"#launch={run['kwargs']['launch_secret']}" in run["printed"]


# ── The page ──────────────────────────────────────────────────────────────────

_LAUNCH_HARNESS = r"""
const vm = require('vm');
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const store = {};
const replaced = [];
const ctx = {
  location: { hash: input.hash, pathname: '/', search: '' },
  sessionStorage: { getItem: (k) => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } },
  history: { replaceState: (s, t, url) => replaced.push(url) },
};
vm.createContext(ctx);
vm.runInContext(input.source, ctx);
const first = ctx.launchHeaders();
ctx.location.hash = '';
const again = ctx.launchHeaders();
process.stdout.write(JSON.stringify({ first, again, replaced }));
"""


def _node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("CI"):
            pytest.fail("node is required to check the served page")
        pytest.skip("node not installed")
    return node


def _page_function(name: str) -> str:
    page = gui._GUI_HTML_TEMPLATE
    start = page.index(f"  function {name}(")
    end = page.index("\n  }\n", start) + len("\n  }\n")
    return page[start:end]


@pytest.mark.parametrize("hash_, expected", [
    ("#launch=" + SECRET, {"X-Artzain-Launch": SECRET}),
    ("", {}),
], ids=["opened-by-the-launcher", "opened-by-hand"])
def test_the_page_keeps_the_secret_for_the_tab_and_drops_it_from_the_address(tmp_path, hash_, expected):
    harness = tmp_path / "launch_harness.js"
    harness.write_text(_LAUNCH_HARNESS, encoding="utf-8")
    source = "const LAUNCH_KEY = 'artzain_gui_launch';\n" + _page_function("launchHeaders")
    proc = subprocess.run([_node(), str(harness)], input=json.dumps({"hash": hash_, "source": source}),
                          capture_output=True, text=True, encoding="utf-8", timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["first"] == expected
    # A reload of the tab keeps it; the address bar no longer shows it.
    assert out["again"] == expected
    assert out["replaced"] == (["/"] if hash_ else [])
