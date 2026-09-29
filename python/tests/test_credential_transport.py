"""An API key goes only to the host it was issued with, by the scheme its base
URL names.

Which host that is was settled by the pairing of each key with its host (see
``test_credential_pairing.py``). Two ways the key still went elsewhere:

* A request answered with a redirect sent the key on to the host the redirect
  named: urllib copies a request's headers onto the request it sends there.
  Every request that carries the key or a session token now follows no
  redirect, and a 3xx is an error status like any other the call did not
  expect. The background sender's POSTs never followed one.
* The background sender used plain HTTP for any scheme but ``https``, so a
  mistyped scheme sent the key unencrypted, and a base URL without one was
  dialled with no host. A base URL a key goes to must now be an ``http://`` or
  ``https://`` URL that names a host; any other is refused before anything is
  sent, by the name of the setting that holds it. ``http://`` keeps working,
  for a deployment on this machine.

The servers are real, on 127.0.0.1: the origin answers every request with a
redirect to the sink, another port and so another origin, which records
whatever reaches it.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import http.client
import importlib
import ipaddress
import json
import logging
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

import pytest

from artzain import cli, cloud, credentials, gui
from artzain.credentials import CredentialConflictError

# The package re-exports the decide() function under the module's name.
decide_mod = importlib.import_module("artzain.decide")

KEY = "cnx_transport_test_0123456789abcdef"
TOKEN = "session-token-the-browser-sent-0123456789"
HOST = "base-url-host.example"
REDIRECTS = (301, 302, 303, 307, 308)
SRC = Path(cloud.__file__).resolve().parent


class _Server:
    """A local HTTP server that records each request, then answers it with
    *answer*; over TLS with *tls*, a server-side context."""

    def __init__(
        self,
        answer: Callable[[BaseHTTPRequestHandler], None],
        tls: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        requests = self.requests

        class _Handler(BaseHTTPRequestHandler):
            def _any(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                requests.append((self.command, self.path, dict(self.headers.items())))
                answer(self)

            do_GET = do_POST = do_PUT = do_DELETE = do_CONNECT = _any

            def log_message(self, *args: Any) -> None:
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        port = self._httpd.server_address[1]
        if tls is not None:
            self._httpd.socket = tls.wrap_socket(self._httpd.socket, server_side=True)
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{port}"
        threading.Thread(target=self._httpd.serve_forever, args=(0.02,), daemon=True).start()

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()

    def carrying(self, secret: str) -> list[tuple[str, str]]:
        """The requests (method, path) whose headers carried *secret*."""
        return [(m, p) for m, p, h in self.requests if any(secret in v for v in h.values())]


def _json(handler: BaseHTTPRequestHandler, body: dict[str, Any], status: int = 200) -> None:
    raw = json.dumps(body).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


#: What the sink answers: enough for every call to read it as a success.
SINK_ANSWER = {
    "ok": True, "rules": [], "entries": [], "total": 0, "anchors": [], "count": 0,
    "outcome": "allow", "decision_id": "from-the-sink",
}


def _redirect(handler: BaseHTTPRequestHandler, code: int, location: str) -> None:
    handler.send_response(code)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def _no_tunnel(handler: BaseHTTPRequestHandler) -> None:
    """A proxy's refusal of a CONNECT."""
    handler.send_response(502)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """No proxy, no ``.env`` from the machine, no session row, a fixed
    User-Agent; a working directory of the test's own."""
    monkeypatch.setattr(cloud.urllib.request, "getproxies", lambda: {})
    monkeypatch.setattr(cloud, "_session_logged", True)
    monkeypatch.setattr(cloud, "_package_version", lambda: "test")
    monkeypatch.setattr(cli, "_iter_dotenv_paths", lambda start=None: iter(()))
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def fresh_opener(monkeypatch: pytest.MonkeyPatch) -> None:
    """No opener kept from an earlier test: a test of how the opener is built
    gets one built under its own settings, whatever ran before it."""
    monkeypatch.setattr(cloud, "_api_opener_built", None)


@pytest.fixture
def sink() -> Iterator[_Server]:
    server = _Server(lambda h: _json(h, SINK_ANSWER))
    yield server
    server.close()


@pytest.fixture(params=REDIRECTS, ids=lambda code: f"HTTP{code}")
def origin(request: pytest.FixtureRequest, sink: _Server) -> Iterator[_Server]:
    code = request.param
    server = _Server(lambda h: _redirect(h, code, sink.url + "/landed" + h.path))
    server.code = code  # type: ignore[attr-defined]
    yield server
    server.close()


# ---------------------------------------------------------------------------
# No redirect is followed
# ---------------------------------------------------------------------------


def _with_configure(origin: str, monkeypatch: pytest.MonkeyPatch) -> None:
    cloud.configure(api_key=KEY, base_url=origin)


def _with_environment(origin: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", origin)


def _rules_get(origin: str, tmp: Path) -> Any:
    return cloud.fetch_client_policy_rules()


def _identity_get(origin: str, tmp: Path) -> Any:
    return cloud.fetch_api_key_identity()


def _probe_post(origin: str, tmp: Path) -> Any:
    return cloud._probe_api_key_via_events()


def _decide_post(origin: str, tmp: Path) -> Any:
    return decide_mod.decide(action="send_email", target="crm:contact:1", payload="hello")


def _event_post(origin: str, tmp: Path) -> Any:
    return cloud.post_sdk_event("generation", payload={"n": 1})


def _decision_post(origin: str, tmp: Path) -> Any:
    return cloud.post_policy_human_decision("approved", request_id="req-1")


def _registry_list(origin: str, tmp: Path) -> Any:
    ns = argparse.Namespace(limit=10, q=None, source=None, lifecycle=None, json=True)
    return cli.cmd_registry_list(ns)


def _policy_promote(origin: str, tmp: Path) -> Any:
    return cli.cmd_policy_promote(argparse.Namespace(bundle_id="bundle-1"))


def _audit_export(origin: str, tmp: Path) -> Any:
    ns = argparse.Namespace(profile=None, from_=None, to=None, out=str(tmp / "audit.zip"))
    return cli.cmd_audit_export(ns)


def _registry_export(origin: str, tmp: Path) -> Any:
    ns = argparse.Namespace(q=None, source=None, lifecycle=None, out=str(tmp / "catalog.csv"))
    return cli.cmd_registry_export(ns)


def _licence_anchors(origin: str, tmp: Path) -> Any:
    ns = argparse.Namespace(base_url=origin, allow_remote=False, limit=10,
                            out=str(tmp / "anchors.json"))
    return cli.cmd_licence_anchors(ns)


def _licence_anchor_post(origin: str, tmp: Path) -> Any:
    anchor = tmp / "anchor.json"
    anchor.write_text("{}", encoding="utf-8")
    ns = argparse.Namespace(base_url=origin, allow_remote=False, anchor=str(anchor))
    return cli.cmd_licence_anchor(ns)


def _gui_bootstrap(origin: str, tmp: Path) -> Any:
    return gui._try_bootstrap(origin, KEY)


def _refused(code: int) -> Callable[[Any, Optional[BaseException]], bool]:
    """A CLI command's refusal: it exits naming the status."""
    return lambda result, exc: isinstance(exc, SystemExit) and f"({code})" in str(exc)


#: Each call that carries the key: how the key and host are set, the call, and
#: what it gives back for an answer that is a redirect (the status: *code*).
CALLS = [
    pytest.param(_with_configure, _rules_get,
                 lambda code: lambda r, e: e is None and r == [], id="rules-get"),
    pytest.param(_with_configure, _identity_get,
                 lambda code: lambda r, e: r["valid"] is False and r["http_status"] == code,
                 id="identity-get"),
    pytest.param(_with_configure, _probe_post,
                 lambda code: lambda r, e: r["valid"] is False and r["http_status"] == code,
                 id="probe-post"),
    pytest.param(_with_configure, _decide_post,
                 lambda code: lambda r, e: (isinstance(e, decide_mod.DecisionError)
                                            and e.status == code),
                 id="decide-post"),
    pytest.param(_with_configure, _event_post, lambda code: lambda r, e: e is None,
                 id="event-post"),
    pytest.param(_with_configure, _decision_post, lambda code: lambda r, e: e is None,
                 id="decision-post"),
    pytest.param(_with_environment, _registry_list, _refused, id="cli-registry-list"),
    pytest.param(_with_environment, _policy_promote, _refused, id="cli-policy-promote"),
    pytest.param(_with_environment, _audit_export, _refused, id="cli-audit-export"),
    pytest.param(_with_environment, _registry_export, _refused, id="cli-registry-export"),
    pytest.param(_with_environment, _licence_anchors,
                 lambda code: lambda r, e: isinstance(e, SystemExit) and e.code == 1,
                 id="cli-licence-get"),
    # A redirect answered to a licence POST is a refusal, not "Stored".
    pytest.param(_with_environment, _licence_anchor_post,
                 lambda code: lambda r, e: isinstance(e, SystemExit) and e.code == 1,
                 id="cli-licence-post"),
    pytest.param(_with_configure, _gui_bootstrap, lambda code: lambda r, e: e is None and r is None,
                 id="gui-bootstrap"),
]


@pytest.mark.parametrize(("settings", "call", "expected"), CALLS)
def test_a_redirect_does_not_take_the_key_to_another_host(
    isolated: Path,
    monkeypatch: pytest.MonkeyPatch,
    artzain_sync_cloud_threads: None,
    origin: _Server,
    sink: _Server,
    settings: Callable[[str, pytest.MonkeyPatch], None],
    call: Callable[[str, Path], Any],
    expected: Callable[[int], Callable[[Any, Optional[BaseException]], bool]],
) -> None:
    code = origin.code  # type: ignore[attr-defined]
    settings(origin.url, monkeypatch)
    result: Any = None
    raised: Optional[BaseException] = None
    try:
        result = call(origin.url, isolated)
    except (Exception, SystemExit) as exc:
        raised = exc

    assert sink.requests == [], f"the redirect was followed: {sink.carrying(KEY)} carried the key"
    assert len(origin.carrying(KEY)) == 1, origin.requests
    assert expected(code)(result, raised), (result, raised)


@pytest.fixture
def gui_proxy(origin: _Server) -> Iterator[str]:
    """``artzain gui``'s proxy, forwarding to the origin, with no API key."""
    handler = gui._make_handler(origin.url, b"<!doctype html>", "")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, args=(0.02,), daemon=True).start()
    yield f"127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize(("method", "body"), [("GET", None), ("POST", b"{}")], ids=["get", "post"])
def test_the_gui_proxy_does_not_take_the_browsers_token_to_another_host(
    isolated: Path,
    origin: _Server,
    sink: _Server,
    gui_proxy: str,
    method: str,
    body: Optional[bytes],
) -> None:
    """The proxy forwards the browser's ``Authorization`` header upstream, and
    relays the status of an answer it does not follow."""
    conn = http.client.HTTPConnection(gui_proxy, timeout=10)
    headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    conn.request(method, "/api/conversations", body=body, headers=headers)
    answer = conn.getresponse()
    answer.read()
    conn.close()

    assert sink.requests == [], f"the redirect was followed: {sink.carrying(TOKEN)} carried the token"
    assert len(origin.carrying(TOKEN)) == 1, origin.requests
    assert answer.status == origin.code  # type: ignore[attr-defined]
    # Nor does the browser follow it: the target is not passed on.
    assert answer.getheader("Location") is None


@pytest.mark.parametrize(
    "call", [_licence_anchors, _licence_anchor_post], ids=["licence-get", "licence-post"]
)
def test_a_licence_refusal_without_a_detail_says_only_the_status(
    isolated: Path,
    monkeypatch: pytest.MonkeyPatch,
    origin: _Server,
    capsys: pytest.CaptureFixture[str],
    call: Callable[[str, Path], Any],
) -> None:
    """A redirect has no body: its refusal is the status, not "HTTP 302: None"."""
    _with_environment(origin.url, monkeypatch)
    with pytest.raises(SystemExit):
        call(origin.url, isolated)
    code = origin.code  # type: ignore[attr-defined]
    lines = capsys.readouterr().err.splitlines()
    assert lines == [f"{origin.url} refused the request (HTTP {code})"], lines


def test_the_sender_logs_a_redirect_as_a_failed_post(
    isolated: Path,
    artzain_sync_cloud_threads: None,
    origin: _Server,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The row did not reach the API, as for any other status that is not a
    success; the warning names the status and where the base URL came from."""
    cloud.configure(api_key=KEY, base_url=origin.url)
    with caplog.at_level(logging.WARNING, logger="artzain.cloud"):
        cloud.post_sdk_event("generation", payload={"n": 1})

    code = origin.code  # type: ignore[attr-defined]
    assert [r.getMessage() for r in caplog.records] == [
        f"cloud: event POST generation failed HTTP {code} (base URL from configure(base_url=...))"
    ]


def test_the_sender_logs_a_300_as_a_failed_post(
    isolated: Path, artzain_sync_cloud_threads: None, caplog: pytest.LogCaptureFixture
) -> None:
    """300 is not a success either, though urllib does not follow it."""
    server = _Server(lambda h: _json(h, {}, status=300))
    try:
        cloud.configure(api_key=KEY, base_url=server.url)
        with caplog.at_level(logging.WARNING, logger="artzain.cloud"):
            cloud.post_sdk_event("generation", payload={"n": 1})
    finally:
        server.close()
    assert [r.getMessage() for r in caplog.records] == [
        "cloud: event POST generation failed HTTP 300 (base URL from configure(base_url=...))"
    ]


def test_an_opener_the_application_installed_is_not_used(
    isolated: Path, monkeypatch: pytest.MonkeyPatch, origin: _Server, sink: _Server
) -> None:
    """``urllib.request.install_opener()``, or any earlier ``urlopen()`` in the
    process, leaves an opener that follows redirects in ``urlopen``'s place."""
    monkeypatch.setattr(cloud.urllib.request, "_opener", cloud.urllib.request.build_opener())
    cloud.configure(api_key=KEY, base_url=origin.url)
    cloud.fetch_api_key_identity()
    assert sink.requests == []


def test_the_gui_bootstrap_logs_no_url(
    isolated: Path, origin: _Server, caplog: pytest.LogCaptureFixture
) -> None:
    """Neither for an answer it will not use (a redirect) nor for a request
    that failed (nothing listening)."""
    with caplog.at_level(logging.DEBUG, logger="artzain.gui"):
        assert gui._try_bootstrap(origin.url, KEY) is None
        assert gui._try_bootstrap("http://127.0.0.1:1", KEY) is None
    assert not [r.getMessage() for r in caplog.records if "127.0.0.1" in r.getMessage()]


def test_a_redirect_to_the_same_host_is_not_followed_either(isolated: Path) -> None:
    """The answer comes from the URL the call asked for, or the call fails:
    none of the API's routes answers with a redirect."""
    rule = {"rule_id": "ACME-elsewhere", "title": "t", "violation_patterns": ["x"]}

    def _answer(handler: BaseHTTPRequestHandler) -> None:
        if handler.path.startswith("/elsewhere"):
            _json(handler, {"rules": [rule]})
        else:
            _redirect(handler, 302, server.url + "/elsewhere" + handler.path)

    server = _Server(_answer)
    try:
        cloud.configure(api_key=KEY, base_url=server.url)
        assert cloud.fetch_client_policy_rules() == []
        assert [p for _m, p, _h in server.requests] == ["/api/policy-enforcement/rules"]
    finally:
        server.close()


# ---------------------------------------------------------------------------
# A base URL is an http(s) URL that names a host
# ---------------------------------------------------------------------------

UNUSABLE = [
    pytest.param(f"htps://{HOST}", id="mistyped-scheme"),
    pytest.param(HOST, id="no-scheme"),
    pytest.param(f"{HOST}:8443", id="no-scheme-with-port"),
    pytest.param(f"ftp://{HOST}", id="another-scheme"),
    pytest.param("https://", id="no-host"),
    pytest.param("https://:8443", id="port-but-no-host"),
    pytest.param("https://user@", id="user-but-no-host"),
    pytest.param(f"https://{HOST}:port", id="port-not-a-number"),
    pytest.param(f"//{HOST}", id="no-scheme-but-slashes"),
    pytest.param(f"httpx://{HOST}", id="scheme-starting-with-http"),
    pytest.param(f"https+unix://{HOST}", id="scheme-extending-https"),
    # No request can carry these: urllib refuses them with an error that
    # quotes the host, percent-decoded first.
    pytest.param("https://" + HOST.replace("-", " ", 1), id="space-in-host"),
    pytest.param(f"https://{HOST}\x7f/api", id="control-character"),
    pytest.param("https://" + HOST.replace("-", "\x01", 1), id="c0-control-character"),
    # urlsplit deletes a tab or a line break before it reads the URL.
    pytest.param(f"https://{HOST}\t/api", id="tab"),
    pytest.param("https://" + HOST.replace("-", "%20", 1), id="encoded-space-in-host"),
    pytest.param("https://" + HOST.replace("-", "%0a", 1), id="encoded-control-character"),
    # A C1 control that no reader takes for a line break, as NEL would be.
    pytest.param("https://" + HOST.replace("-", "\x9b", 1), id="c1-control-character"),
    pytest.param(f"https://user:secret@{HOST}", id="user-and-password"),
    pytest.param(f"https://user@{HOST}", id="user-without-password"),
    pytest.param(f"https://@{HOST}", id="empty-user"),
    pytest.param(f"https://:@{HOST}", id="empty-user-and-password"),
]


def _from_configure(value: str, monkeypatch: pytest.MonkeyPatch, tmp: Path) -> tuple[Any, str]:
    return lambda: credentials.resolve_credentials(api_key=KEY, base_url=value), "configure(base_url=...)"


def _from_environment(value: str, monkeypatch: pytest.MonkeyPatch, tmp: Path) -> tuple[Any, str]:
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", value)
    return lambda: credentials.resolve_credentials(api_key=KEY), "COGNEXUS_API_BASE_URL"


def _from_profile(value: str, monkeypatch: pytest.MonkeyPatch, tmp: Path) -> tuple[Any, str]:
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp / "credentials.toml"))
    credentials.write_profile(api_key=KEY, base_url=value)
    return lambda: credentials.resolve_credentials(), credentials.PROFILE_SOURCE


def _from_dotenv(value: str, monkeypatch: pytest.MonkeyPatch, tmp: Path) -> tuple[Any, str]:
    label = str(tmp / "project" / ".env")
    return lambda: credentials.resolve_credentials(dotenv=(KEY, value, label)), label


SOURCES = [
    pytest.param(_from_configure, id="configure"),
    pytest.param(_from_environment, id="environment"),
    pytest.param(_from_profile, id="profile"),
    pytest.param(_from_dotenv, id="dotenv"),
]


@pytest.mark.parametrize("value", UNUSABLE)
@pytest.mark.parametrize("source", SOURCES)
def test_a_key_is_not_paired_with_a_base_url_that_is_not_http_or_https(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, source: Callable[..., Any], value: str
) -> None:
    """Refused before anything is sent: a CredentialConflictError, which every
    caller already reads as "not sent". Its message names the setting, never
    the value."""
    resolve, label = source(value, monkeypatch, tmp_path)
    with pytest.raises(CredentialConflictError) as refused:
        resolve()
    message = str(refused.value)
    assert label in message, message
    assert "host.example" not in message.lower(), message
    assert "secret" not in message and KEY not in message, message


@pytest.mark.parametrize(
    "value",
    [
        f"https://{HOST}",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "HTTPS://Base-URL-Host.Example",
        "https://[::1]:8443",
    ],
)
def test_an_http_or_https_base_url_is_used(value: str) -> None:
    """``http://`` included: a deployment on this machine, such as the one
    ``artzain local`` runs, is reached over plain HTTP."""
    resolved = credentials.resolve_credentials(api_key=KEY, base_url=value)
    assert (resolved.api_key, resolved.base_url) == (KEY, value)


def test_with_no_key_any_base_url_still_resolves() -> None:
    """No key is sent; the base URL is only shown."""
    resolved = credentials.resolve_credentials(base_url=f"htps://{HOST}")
    assert (resolved.api_key, resolved.base_url) == (None, f"htps://{HOST}")


@pytest.mark.parametrize("pairing", ["profile", "dotenv"])
def test_a_set_host_no_key_can_go_to_is_named_as_such_when_the_key_is_paired(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pairing: str
) -> None:
    """The profile or a ``.env`` pairs its key with a host of its own; a set
    host that is no http(s) URL at all is reported as that, not as a
    different host."""
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", f"htps://{HOST}")
    dotenv: Optional[tuple[str, Optional[str], str]] = None
    if pairing == "profile":
        monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp_path / "credentials.toml"))
        credentials.write_profile(api_key=KEY, base_url="https://profile-host.example")
    else:
        dotenv = (KEY, "https://dotenv-host.example", str(tmp_path / ".env"))
    with pytest.raises(CredentialConflictError) as refused:
        credentials.resolve_credentials(dotenv=dotenv)
    message = str(refused.value)
    assert "is not an http:// or https:// URL" in message, message
    assert "COGNEXUS_API_BASE_URL" in message and "different host" not in message, message


def test_the_setting_named_is_the_one_holding_the_url_not_the_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A key set at run time that equals the profile's goes to the profile's
    host; when that host is unusable, the profile is the setting to correct."""
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp_path / "credentials.toml"))
    credentials.write_profile(api_key=KEY, base_url=f"htps://{HOST}")
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    with pytest.raises(CredentialConflictError) as refused:
        credentials.resolve_credentials()
    message = str(refused.value)
    assert credentials.PROFILE_SOURCE in message and "COGNEXUS_API_KEY" not in message, message


class _Listener:
    """A plain TCP listener that records the bytes of each connection made to
    it and answers each with an empty 204."""

    def __init__(self) -> None:
        self.received: list[bytes] = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(2)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                except OSError:
                    pass
                # Recorded before the answer, which the sender waits for.
                self.received.append(data)
                try:
                    conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()


@pytest.fixture
def listener() -> Iterator[_Listener]:
    server = _Listener()
    yield server
    server.close()


def test_a_mistyped_scheme_sends_nothing_unencrypted(
    isolated: Path,
    listener: _Listener,
    artzain_sync_cloud_threads: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``htps://`` used to reach the host over plain HTTP, the key in the
    request. Nothing is sent now, and the warning names the setting."""
    base = f"htps://127.0.0.1:{listener.port}"
    cloud.configure(api_key=KEY, base_url=base)
    with caplog.at_level(logging.WARNING, logger="artzain"):
        cloud.post_sdk_event("generation", payload={"n": 1})
        cloud.post_policy_human_decision("approved", request_id="req-1")
        assert cloud.fetch_client_policy_rules() == []

    assert listener.received == []
    lines = [r.getMessage() for r in caplog.records]
    assert any("configure(base_url=...)" in m for m in lines), lines
    assert not [m for m in lines if str(listener.port) in m or KEY in m], lines


def test_a_base_url_without_a_scheme_dials_nothing(
    isolated: Path, monkeypatch: pytest.MonkeyPatch, artzain_sync_cloud_threads: None
) -> None:
    """With no scheme there is no host either: the sender dialled one that
    was empty, which reaches this machine."""
    dialled: list[tuple[Any, Any]] = []

    class _Refuse:
        def __init__(self, host: Any, port: Any = None, **kw: Any) -> None:
            dialled.append((host, port))
            raise OSError("no connection in this test")

    monkeypatch.setattr(cloud.http.client, "HTTPConnection", _Refuse)
    monkeypatch.setattr(cloud.http.client, "HTTPSConnection", _Refuse)
    for base in ("127.0.0.1:8000", "localhost:8000", HOST):
        cloud.configure(api_key=KEY, base_url=base)
        cloud.post_sdk_event("generation", payload={"n": 1})
        cloud.post_policy_human_decision("approved", request_id="req-1")
    assert dialled == []


def test_decide_refuses_a_mistyped_scheme_by_the_settings_name(
    isolated: Path, listener: _Listener
) -> None:
    base = f"htps://127.0.0.1:{listener.port}"
    cloud.configure(api_key=KEY, base_url=base)
    with pytest.raises(decide_mod.DecisionError) as refused:
        decide_mod.decide(action="send_email", target="crm:contact:1", payload="hello")
    message = str(refused.value)
    assert "not sent" in message and "configure(base_url=...)" in message, message
    assert str(listener.port) not in message and KEY not in message, message
    assert listener.received == []


def test_the_cli_refuses_a_mistyped_scheme_by_the_settings_name(
    isolated: Path, monkeypatch: pytest.MonkeyPatch, listener: _Listener
) -> None:
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", f"htps://127.0.0.1:{listener.port}")
    with pytest.raises(SystemExit) as refused:
        _registry_list("", isolated)
    message = str(refused.value)
    assert "COGNEXUS_API_BASE_URL" in message, message
    assert str(listener.port) not in message and KEY not in message, message
    assert listener.received == []


def test_http_still_reaches_a_deployment_on_this_machine(
    isolated: Path, artzain_sync_cloud_threads: None
) -> None:
    server = _Server(lambda h: _json(h, {"ok": True}))
    try:
        cloud.configure(api_key=KEY, base_url=server.url)
        cloud.post_sdk_event("generation", payload={"n": 1})
        assert server.carrying(KEY) == [("POST", "/api/events")]
    finally:
        server.close()


@pytest.mark.parametrize(
    "url",
    [
        "htps://127.0.0.1:1/api/events",
        "127.0.0.1:1/api/events",
        "https:///api/events",
    ],
    ids=["mistyped-scheme", "no-scheme", "no-host"],
)
def test_the_sender_dials_only_an_http_or_https_url_with_a_host(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    """Whatever it is handed: the base URL is checked where the credentials
    are resolved, and the sender refuses any other URL too."""
    dialled: list[tuple[Any, Any]] = []

    class _Refuse:
        def __init__(self, host: Any, port: Any = None, **kw: Any) -> None:
            dialled.append((host, port))
            raise OSError("no connection in this test")

    monkeypatch.setattr(cloud.http.client, "HTTPConnection", _Refuse)
    monkeypatch.setattr(cloud.http.client, "HTTPSConnection", _Refuse)
    with pytest.raises(ValueError) as refused:
        cloud._CloudTransport().post(url, b"{}", {"X-Api-Key": KEY}, 1.0)
    assert dialled == []
    assert "127.0.0.1" not in str(refused.value), refused.value


def test_the_sender_refuses_before_it_opens_a_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[tuple[Any, ...]] = []
    monkeypatch.setattr(cloud._CloudTransport, "_open", staticmethod(lambda *a: opened.append(a)))
    with pytest.raises(ValueError):
        cloud._CloudTransport().post("htps://127.0.0.1:1/api/events", b"{}", {}, 1.0)
    assert opened == []


def test_the_senders_connection_is_http_or_https_only() -> None:
    """Whatever calls it: no plain connection for another scheme."""
    with pytest.raises(ValueError):
        cloud._CloudTransport._open("htps", "127.0.0.1", 1, 1.0)


# ---------------------------------------------------------------------------
# No module sends a request through urllib's default opener
# ---------------------------------------------------------------------------

#: Functions that call ``urlopen`` and may: none sends a key or a token. The
#: release manifest is public, and its host may redirect to a download; the
#: local engine's health check and sign-in send a password only in the body,
#: which urllib does not send on to a redirect.
_URLOPEN_ALLOWED = {
    ("local.py", "load_manifest"),
    ("local.py", "_get_json"),
    ("local.py", "_api_post"),
}


def _calls(path: Path) -> Iterator[tuple[str, str]]:
    """(innermost enclosing function, dotted name) of every call in *path*."""

    def _dotted(func: ast.expr) -> str:
        parts: list[str] = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        return ".".join(reversed(parts))

    def _walk(node: ast.AST, owner: str) -> Iterator[tuple[str, str]]:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield from _walk(child, child.name)
                continue
            if isinstance(child, ast.Call):
                yield owner, _dotted(child.func)
            yield from _walk(child, owner)

    yield from _walk(ast.parse(path.read_text(encoding="utf-8")), "<module>")


def test_no_request_carrying_a_key_uses_urllibs_default_opener() -> None:
    """``urlopen``, and an opener from ``build_opener``, follow redirects with
    the request's headers. A request to the API goes through
    ``artzain.cloud._urlopen``."""
    found = [
        (path.name, owner, name)
        for path in sorted(SRC.glob("*.py"))
        for owner, name in _calls(path)
        if name.split(".")[-1] in ("urlopen", "build_opener")
        and (path.name, owner) not in _URLOPEN_ALLOWED
    ]
    assert found == []


def test_the_api_opener_opens_http_and_https_urls_only(
    fresh_opener: None, tmp_path: Path
) -> None:
    """No file, FTP or data URL: the API is reached over HTTP(S)."""
    target = tmp_path / "rules.json"
    target.write_text("{}", encoding="utf-8")
    for url in (target.as_uri(), "ftp://127.0.0.1:1/rules.json", "data:,{}"):
        with pytest.raises(cloud.urllib.error.URLError) as refused:
            cloud._urlopen(cloud.urllib.request.Request(url), timeout=1.0)
        # Refused as a scheme, not a connection that failed.
        assert "unknown url type" in str(refused.value.reason), (url, refused.value.reason)


def test_the_api_opener_takes_only_the_http_and_https_proxies(
    fresh_opener: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A proxy set for another scheme (an ``ftp_proxy``, or the one system
    proxy Windows gives every scheme) would take a request for that scheme,
    headers and all, to the proxy over plain HTTP."""
    proxy = _Server(lambda h: _json(h, {}))
    try:
        monkeypatch.setattr(
            cloud.urllib.request,
            "getproxies",
            lambda: {"ftp": proxy.url, "file": proxy.url, "data": proxy.url},
        )
        target = tmp_path / "rules.json"
        target.write_text("{}", encoding="utf-8")
        for url in ("ftp://127.0.0.1:1/rules.json", target.as_uri(), "data:,{}"):
            request = cloud.urllib.request.Request(url, headers={"X-Api-Key": KEY})
            with pytest.raises(cloud.urllib.error.URLError):
                cloud._urlopen(request, timeout=5.0)
    finally:
        proxy.close()
    assert proxy.requests == []


def test_the_api_opener_goes_through_the_http_and_https_proxies(
    fresh_opener: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """As ``urlopen`` did: an HTTP proxy is sent the whole request, an HTTPS
    one only a CONNECT for the host, without the key. (The API host is on this
    machine, so a request that went around the proxy stays here too.)"""
    proxy = _Server(lambda h: _no_tunnel(h) if h.command == "CONNECT" else _json(h, {"ok": True}))
    try:
        monkeypatch.setattr(
            cloud.urllib.request, "getproxies", lambda: {"http": proxy.url, "https": proxy.url}
        )
        monkeypatch.setattr(cloud.urllib.request, "proxy_bypass", lambda host: False)
        headers = {"X-Api-Key": KEY}
        request = cloud.urllib.request.Request("http://127.0.0.2:9/api/x", headers=headers)
        with cloud._urlopen(request, timeout=5.0) as answer:
            assert answer.status == 200
        request = cloud.urllib.request.Request("https://127.0.0.2:9/api/x", headers=headers)
        with pytest.raises(cloud.urllib.error.URLError):
            cloud._urlopen(request, timeout=5.0)
    finally:
        proxy.close()
    assert [(m, p) for m, p, _h in proxy.requests] == [
        ("GET", "http://127.0.0.2:9/api/x"),
        ("CONNECT", "127.0.0.2:9"),
    ]
    assert proxy.carrying(KEY) == [("GET", "http://127.0.0.2:9/api/x")]


def test_the_api_opener_speaks_tls_to_an_https_url(
    fresh_opener: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first bytes it sends to an ``https://`` host open a TLS handshake."""
    monkeypatch.setattr(cloud.urllib.request, "getproxies", lambda: {})
    first: list[bytes] = []
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)

    def _accept() -> None:
        try:
            conn, _ = server.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(5)
            try:
                first.append(conn.recv(5))
            except OSError:
                first.append(b"")

    thread = threading.Thread(target=_accept, daemon=True)
    thread.start()
    port = server.getsockname()[1]
    try:
        with pytest.raises(cloud.urllib.error.URLError):
            cloud._urlopen(cloud.urllib.request.Request(f"https://127.0.0.1:{port}/x"), timeout=5.0)
    finally:
        thread.join(timeout=5)
        server.close()
    assert first and first[0][:1] == b"\x16", first  # a TLS handshake record


def _self_signed(tmp: Path) -> tuple[Path, Path]:
    """A certificate for 127.0.0.1 that no trust store holds, and its key."""
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_the_api_opener_verifies_the_servers_certificate(
    fresh_opener: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A server whose certificate no trusted authority issued is not sent the
    request, key and all: the opener's TLS context is a verifying one."""
    monkeypatch.setattr(cloud.urllib.request, "getproxies", lambda: {})
    cert, key = _self_signed(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = _Server(lambda h: _json(h, {"ok": True}), tls=context)
    try:
        request = cloud.urllib.request.Request(
            server.url + "/api/api-keys/me", headers={"X-Api-Key": KEY}
        )
        with pytest.raises(cloud.urllib.error.URLError) as refused:
            cloud._urlopen(request, timeout=5.0)
        assert isinstance(refused.value.reason, ssl.SSLCertVerificationError), refused.value
    finally:
        server.close()
    assert server.requests == []


class _Silent:
    """A server that accepts connections and never answers. It hangs up on
    each after *hold* seconds, so a call that waits past its timeout ends in a
    failed test rather than one that never returns."""

    def __init__(self, hold: float = 8.0) -> None:
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._hold = hold
        self._held: list[socket.socket] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn = self._sock.accept()[0]
            except OSError:
                continue
            self._held.append(conn)
            timer = threading.Timer(self._hold, conn.close)
            timer.daemon = True
            timer.start()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        for conn in self._held:
            conn.close()
        self._sock.close()


def test_a_call_to_an_api_that_never_answers_ends_at_its_timeout(isolated: Path) -> None:
    """The timeout a call is given reaches the request it makes."""
    silent = _Silent()
    try:
        cloud.configure(api_key=KEY, base_url=f"http://127.0.0.1:{silent.port}")
        started = time.monotonic()
        with pytest.raises(decide_mod.DecisionError):
            decide_mod.decide(
                action="send_email", target="crm:contact:1", payload="hello", timeout_sec=0.5
            )
        assert time.monotonic() - started < 4.0
    finally:
        silent.close()


def test_the_api_opener_is_built_once_for_a_proxy_setting(
    fresh_opener: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Building one builds a TLS context, which loads the certificate store:
    tens of milliseconds on every ``decide()``. The proxies are still read for
    each request, so a changed setting takes effect on the next one; a proxy
    for another scheme, which it does not use, is no change."""
    monkeypatch.setattr(cloud.urllib.request, "getproxies", lambda: {})
    first = cloud._api_opener()
    assert cloud._api_opener() is first
    monkeypatch.setattr(cloud.urllib.request, "getproxies", lambda: {"ftp": "http://127.0.0.1:1"})
    assert cloud._api_opener() is first
    monkeypatch.setattr(
        cloud.urllib.request, "getproxies", lambda: {"https": "http://127.0.0.1:1"}
    )
    assert cloud._api_opener() is not first


@pytest.mark.parametrize("variable", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
def test_the_api_opener_is_built_again_for_other_certificates(
    fresh_opener: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, variable: str
) -> None:
    """A TLS context reads the certificates it trusts when it is made."""
    monkeypatch.setattr(cloud.urllib.request, "getproxies", lambda: {})
    monkeypatch.delenv(variable, raising=False)
    first = cloud._api_opener()
    monkeypatch.setenv(variable, str(tmp_path))
    assert cloud._api_opener() is not first


def test_the_api_opener_does_not_keep_a_tls_default_that_was_relaxed(
    fresh_opener: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An application that turns verification off for the process and then
    back on (``ssl._create_default_https_context``, as PEP 476 describes)
    leaves no unverified context behind for the key's requests."""
    monkeypatch.setattr(cloud.urllib.request, "getproxies", lambda: {})
    cert, key = _self_signed(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = _Server(lambda h: _json(h, {"ok": True}), tls=context)
    verifying = ssl._create_default_https_context
    try:
        # Built while verification is off (fresh_opener: not one kept before).
        monkeypatch.setattr(ssl, "_create_default_https_context", ssl._create_unverified_context)
        cloud._api_opener()
        monkeypatch.setattr(ssl, "_create_default_https_context", verifying)
        request = cloud.urllib.request.Request(
            server.url + "/api/api-keys/me", headers={"X-Api-Key": KEY}
        )
        with pytest.raises(cloud.urllib.error.URLError) as refused:
            cloud._urlopen(request, timeout=5.0)
        assert isinstance(refused.value.reason, ssl.SSLCertVerificationError), refused.value
    finally:
        server.close()
    assert server.requests == []


def _no_content(handler: BaseHTTPRequestHandler) -> None:
    handler.send_response(204)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


@pytest.mark.parametrize("status", [201, 204])
def test_a_licence_post_answered_with_another_success_is_one(
    isolated: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: int,
) -> None:
    """Only a redirect or an error is a refusal: 201 and 204 are successes."""
    answer = {"last_seq": 7, "anchored_at": "2026-09-29T00:00:00Z"}
    deployment = _Server(
        (lambda h: _json(h, answer, status=201)) if status == 201 else _no_content
    )
    try:
        _with_environment(deployment.url, monkeypatch)
        _licence_anchor_post(deployment.url, isolated)
    finally:
        deployment.close()
    assert "Stored anchor for seq" in capsys.readouterr().out


def test_a_licence_url_is_read_without_the_blanks_around_it(
    isolated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``--base-url`` with blanks or a line break around it, as a shell or a
    file can leave, reaches the deployment it names."""
    deployment = _Server(lambda h: _json(h, {"anchors": [], "count": 0}))
    try:
        monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
        ns = argparse.Namespace(
            base_url=f" {deployment.url}/\n",
            allow_remote=False,
            limit=10,
            out=str(isolated / "anchors.json"),
        )
        cli.cmd_licence_anchors(ns)
    finally:
        deployment.close()
    assert deployment.carrying(KEY) == [("GET", "/api/v1/licence/anchors?limit=10")]


@pytest.mark.parametrize(
    ("flag", "variable", "label"),
    [
        pytest.param("ftp://127.0.0.1:{port}", None, "--base-url", id="flag"),
        pytest.param(None, "htps://127.0.0.1:{port}", "COGNEXUS_LOCAL_URL", id="environment"),
    ],
)
def test_the_licence_commands_send_the_key_only_to_an_http_or_https_url(
    isolated: Path,
    monkeypatch: pytest.MonkeyPatch,
    listener: _Listener,
    flag: Optional[str],
    variable: Optional[str],
    label: str,
) -> None:
    """They take the deployment's URL from ``--base-url`` or
    ``COGNEXUS_LOCAL_URL`` and checked only that its host is this machine. A
    proxy set for the scheme would have been sent the request, key and all."""
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    proxy = f"http://127.0.0.1:{listener.port}"
    monkeypatch.setattr(cloud.urllib.request, "getproxies", lambda: {"ftp": proxy, "htps": proxy})
    if variable:
        monkeypatch.setenv("COGNEXUS_LOCAL_URL", variable.format(port=listener.port))
    ns = argparse.Namespace(
        base_url=flag.format(port=listener.port) if flag else None,
        allow_remote=False,
        limit=10,
        out=str(isolated / "anchors.json"),
    )
    with pytest.raises(SystemExit) as refused:
        cli.cmd_licence_anchors(ns)
    message = str(refused.value)
    assert label in message, message
    assert str(listener.port) not in message and KEY not in message, message
    assert listener.received == []
