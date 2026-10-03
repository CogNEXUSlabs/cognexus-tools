"""The sidecar's connection to the engine: one origin, an explicit proxy, an
explicit set of certificate authorities, and connections that are kept.

Until now the sidecar called the engine through the SDK's general opener:

* every call opened a new connection, so every governed write paid for the
  TCP and TLS handshakes inside the gateway's interceptor timeout;
* the proxy was whatever the environment said, which on a gateway host is
  whatever the last tool that ran there exported, and a corporate network
  that inspects TLS had no setting for its certificate authority.

These tests run against real loopback servers: an engine that keeps
connections, a ``CONNECT`` proxy, and TLS under a certificate authority made
for the test.
"""

from __future__ import annotations

import datetime
import http.client
import ipaddress
import json
import logging
import socket
import ssl
import threading
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from artzain.openshell import sidecar, transport
from artzain.openshell.journal import Journal
from artzain.openshell.state import GatewayLedger

KEY = "cnx_sidecar_test_key"
HEADERS = {"X-Api-Key": KEY, "Accept": "application/json"}


# ---------------------------------------------------------------------------
# The servers
# ---------------------------------------------------------------------------


class _Engine:
    """A loopback engine that speaks HTTP/1.1 and keeps connections.

    ``script`` is a list of per-request behaviours: ``"ok"`` answers 200
    ``{}``; ``("sleep", s)`` answers after *s* seconds; ``"close"`` answers
    and says it will close; ``"drop"`` reads the request and closes without
    answering; ``("answer", status, headers, raw)`` answers exactly that;
    ``("drip", seconds)`` sends its headers at once and its body a byte at
    a time over that long. Each request records the client port it came from.
    ``connections`` counts the connections that were accepted.
    """

    def __init__(self, script=(), *, tls=None):
        self.script = list(script)
        self.requests = []
        self.connections = 0
        self._clients = []
        engine = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                return None

            def setup(self):
                super().setup()
                engine.connections += 1
                engine._clients.append(self.connection)

            def _answer(self, status=200, raw=b"{}", headers=()):
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except OSError:
                    pass

            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                engine.requests.append({"method": self.command, "path": self.path,
                                        "headers": dict(self.headers.items()), "body": body,
                                        "port": self.client_address[1]})
                step = engine.script.pop(0) if engine.script else "ok"
                if step == "drop":
                    self.close_connection = True
                    return
                if isinstance(step, tuple) and step[0] == "sleep":
                    time.sleep(step[1])
                    step = "ok"
                if isinstance(step, tuple) and step[0] == "drip":
                    raw = b'{"a": "' + b"x" * 20 + b'"}'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    try:
                        for index in range(len(raw)):
                            self.wfile.write(raw[index:index + 1])
                            self.wfile.flush()
                            time.sleep(step[1] / len(raw))
                    except OSError:
                        self.close_connection = True
                    return
                if step == "ok":
                    self._answer()
                elif step == "close":
                    self.close_connection = True
                    self._answer(headers=[("Connection", "close")])
                else:
                    _kind, status, headers, raw = step
                    self._answer(status, raw, headers)

            do_GET = do_POST = _serve  # noqa: N815 - stdlib hooks

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False

        self.server = Server(("127.0.0.1", 0), Handler)
        if tls is not None:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.url = "%s://127.0.0.1:%d" % ("https" if tls is not None else "http", self.port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close_kept_connections(self):
        """Close every connection from this side, as a load balancer does to
        one it has not heard from."""
        for client in self._clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self._clients.clear()
        time.sleep(0.1)  # let the close reach the other end

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class _Proxy:
    """A loopback HTTP proxy that answers ``CONNECT`` and relays bytes.

    ``connects`` is every request line it was sent with that request's
    headers; ``relayed`` is every byte it carried from the client. With
    *require*, a ``CONNECT`` without that ``Proxy-Authorization`` is
    answered 407.
    """

    def __init__(self, *, require=None):
        self.require = require
        self.connects = []
        self.relayed = bytearray()
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        self.url = "http://127.0.0.1:%d" % self.port
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                client, _addr = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client):
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
            lines = head.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
            headers = {name.strip().lower(): value.strip()
                       for name, _, value in (line.partition(":") for line in lines[1:])}
            self.connects.append((lines[0], headers))
            method, target, _version = lines[0].split(" ")
            if method != "CONNECT":
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
            if self.require is not None and headers.get("proxy-authorization") != self.require:
                client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                               b"Content-Length: 0\r\n\r\n")
                return
            host, _, port = target.rpartition(":")
            upstream = socket.create_connection((host, int(port)), timeout=5)
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            threading.Thread(target=self._pipe, args=(upstream, client, False),
                             daemon=True).start()
            self._pipe(client, upstream, True)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _pipe(self, source, sink, record):
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                if record:
                    self.relayed += data
                sink.sendall(data)
        except OSError:
            pass
        finally:
            for end in (source, sink):
                try:
                    end.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self):
        self._listener.close()


@pytest.fixture
def servers():
    made = []

    def start(kind, *args, **kwargs):
        server = kind(*args, **kwargs)
        made.append(server)
        return server

    yield start
    for server in made:
        server.close()


@pytest.fixture(autouse=True)
def _no_ambient_settings(monkeypatch):
    for name in ("OPENSHELL_SIDECAR_PROXY", "OPENSHELL_SIDECAR_CA_BUNDLE", "ARTZAIN_DECISION_URL",
                 "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY",
                 "all_proxy", "NO_PROXY", "no_proxy", "OPENSHELL_SIDECAR_JOURNAL",
                 "OPENSHELL_SIDECAR_DECIDE_TIMEOUT_MS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENSHELL_GATEWAY_ID", "gw-a")
    monkeypatch.setenv("COGNEXUS_API_KEY", KEY)
    monkeypatch.setattr(sidecar, "_LEDGER", GatewayLedger(gateway_id="gw-a"))
    monkeypatch.setattr(sidecar, "_JOURNAL", Journal())
    monkeypatch.setattr(sidecar, "_CLIENT", None)


def _client(url, **settings):
    origin = transport._origin(url)
    return transport.EngineClient(transport.Settings(*origin, **settings))


def _deadline(seconds=5.0):
    return time.monotonic() + seconds


def _connections(engine, expected):
    """The connections the engine has accepted, once the thread that
    counts them has had its turn."""
    until = time.monotonic() + 2.0
    while engine.connections != expected and time.monotonic() < until:
        time.sleep(0.01)
    return engine.connections


def _get(client, url, path="/x", **kwargs):
    kwargs.setdefault("deadline", _deadline())
    return client.request("GET", url + path, headers=HEADERS, **kwargs)


# ---------------------------------------------------------------------------
# The settings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", ["", "  ", "engine.example", "ftp://engine.example",
                                 "file:///etc/passwd", "https://", "https://engine.example:port",
                                 "https://[::1", "https://engine.example:99999"])
def test_no_engine_is_configured_without_an_http_url(url):
    assert transport.settings_from_environment({"ARTZAIN_DECISION_URL": url}) is None


@pytest.mark.parametrize("url, origin", [
    ("https://engine.example", ("https", "engine.example", 443)),
    ("HTTPS://Engine.Example/api/v1/decisions", ("https", "engine.example", 443)),
    ("https://engine.example:8443/", ("https", "engine.example", 8443)),
    ("http://127.0.0.1:8000", ("http", "127.0.0.1", 8000)),
    ("http://localhost", ("http", "localhost", 80)),
    ("https://user:secret@engine.example", ("https", "engine.example", 443)),
])
def test_the_origin_is_the_urls_scheme_host_and_port(url, origin):
    settings = transport.settings_from_environment({"ARTZAIN_DECISION_URL": url})
    assert settings.origin == origin
    assert (settings.proxy, settings.ca_bundle) == (None, "")


def test_the_environments_proxy_is_ignored_unless_the_setting_says_env(monkeypatch):
    monkeypatch.setenv("https_proxy", "http://ambient.example:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient.example:3128")
    env = {"ARTZAIN_DECISION_URL": "https://engine.example"}
    assert transport.settings_from_environment(env).proxy is None

    env["OPENSHELL_SIDECAR_PROXY"] = "env"
    assert transport.settings_from_environment(env).proxy == transport.Proxy(
        "ambient.example", 3128)
    env["OPENSHELL_SIDECAR_PROXY"] = " ENV "
    assert transport.settings_from_environment(env).proxy == transport.Proxy(
        "ambient.example", 3128)


def test_env_takes_the_proxy_for_the_engines_scheme_and_honours_no_proxy(monkeypatch):
    monkeypatch.setenv("http_proxy", "http://for-http.example:8080")
    monkeypatch.setenv("https_proxy", "for-https.example:3128")  # no scheme: an http proxy
    env = {"OPENSHELL_SIDECAR_PROXY": "env"}
    https = transport.settings_from_environment(
        {**env, "ARTZAIN_DECISION_URL": "https://engine.example"})
    assert https.proxy == transport.Proxy("for-https.example", 3128)
    http = transport.settings_from_environment(
        {**env, "ARTZAIN_DECISION_URL": "http://engine.example"})
    assert http.proxy == transport.Proxy("for-http.example", 8080)

    monkeypatch.setenv("no_proxy", "engine.example")
    monkeypatch.setenv("NO_PROXY", "engine.example")
    assert transport.settings_from_environment(
        {**env, "ARTZAIN_DECISION_URL": "https://engine.example"}).proxy is None


def test_env_with_no_proxy_in_the_environment_is_direct():
    assert transport.settings_from_environment(
        {"ARTZAIN_DECISION_URL": "https://engine.example",
         "OPENSHELL_SIDECAR_PROXY": "env"}).proxy is None


@pytest.mark.parametrize("raw, proxy", [
    ("http://proxy.example:3128", transport.Proxy("proxy.example", 3128)),
    ("http://proxy.example", transport.Proxy("proxy.example", 80)),
    (" HTTP://Proxy.Example:8080/ ", transport.Proxy("proxy.example", 8080)),
    ("http://ops:s3cret@proxy.example:3128",
     transport.Proxy("proxy.example", 3128, "Basic b3BzOnMzY3JldA==")),
    ("http://ops%40corp:p%3Ass@proxy.example:3128",   # ops@corp / p:ss
     transport.Proxy("proxy.example", 3128, "Basic b3BzQGNvcnA6cDpzcw==")),
    ("http://ops@proxy.example:3128", transport.Proxy("proxy.example", 3128, "Basic b3BzOg==")),
])
def test_a_proxy_setting_is_an_http_proxy_with_optional_credentials(raw, proxy):
    settings = transport.settings_from_environment(
        {"ARTZAIN_DECISION_URL": "https://engine.example", "OPENSHELL_SIDECAR_PROXY": raw})
    assert settings.proxy == proxy


@pytest.mark.parametrize("raw", ["https://ops:s3cret@proxy.example:3128",
                                 "socks5://ops:s3cret@proxy.example:1080",
                                 "ops:s3cret@proxy.example:3128", "proxy.example:3128",
                                 "http://ops:s3cret@:3128", "http://ops:s3cret@proxy.example:port",
                                 "http://"])
def test_a_proxy_setting_that_cannot_be_honoured_is_an_error_not_a_direct_connection(raw):
    with pytest.raises(transport.SettingsError) as refused:
        transport.settings_from_environment(
            {"ARTZAIN_DECISION_URL": "https://engine.example", "OPENSHELL_SIDECAR_PROXY": raw})
    message = str(refused.value)
    assert message.startswith("OPENSHELL_SIDECAR_PROXY ")
    assert "s3cret" not in message and "ops" not in message


def test_a_proxys_credentials_stay_out_of_what_is_printed():
    settings = transport.settings_from_environment(
        {"ARTZAIN_DECISION_URL": "https://engine.example",
         "OPENSHELL_SIDECAR_PROXY": "http://ops:s3cret@proxy.example:3128"})
    for shown in (repr(settings), str(settings), repr(settings.proxy),
                  json.dumps(transport.describe(settings))):
        assert "b3Bz" not in shown and "s3cret" not in shown, shown
    assert transport.describe(settings) == {
        "engine": "https://engine.example:443", "proxy": "proxy.example:3128", "ca_bundle": False}
    assert transport.describe(None) == {"engine": None}


def test_a_certificate_bundle_that_is_not_there_is_an_error(tmp_path):
    env = {"ARTZAIN_DECISION_URL": "https://engine.example",
           "OPENSHELL_SIDECAR_CA_BUNDLE": str(tmp_path / "missing.pem")}
    with pytest.raises(transport.SettingsError, match="OPENSHELL_SIDECAR_CA_BUNDLE"):
        transport.settings_from_environment(env)

    not_pem = tmp_path / "ca.pem"
    not_pem.write_text("not a certificate")
    env["OPENSHELL_SIDECAR_CA_BUNDLE"] = str(not_pem)
    settings = transport.settings_from_environment(env)
    assert settings.ca_bundle == str(not_pem)
    with pytest.raises(transport.SettingsError, match="OPENSHELL_SIDECAR_CA_BUNDLE"):
        transport.EngineClient(settings)


def test_the_tls_context_always_checks_the_certificate_and_the_host_name():
    context = transport.tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


# ---------------------------------------------------------------------------
# One origin
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("other", ["http://127.0.0.1:1/x", "https://127.0.0.1:{port}/x",
                                   "http://localhost:{port}/x", "http://127.0.0.2:{port}/x",
                                   "//127.0.0.1:{port}/x", "/x", "ftp://127.0.0.1:{port}/x"])
def test_a_request_for_another_origin_is_refused_before_a_connection(servers, other):
    engine = servers(_Engine)
    client = _client(engine.url)
    with pytest.raises(ValueError, match="not the engine's origin"):
        client.request("GET", other.format(port=engine.port), headers=HEADERS,
                       deadline=_deadline())
    assert engine.connections == 0


def test_a_redirect_is_an_answer_and_nothing_is_followed(servers):
    elsewhere = servers(_Engine)
    engine = servers(_Engine, [("answer", 302, [("Location", elsewhere.url + "/taken")], b"")])
    status, headers, body = _get(_client(engine.url), engine.url)
    assert (status, headers["Location"], body) == (302, elsewhere.url + "/taken", b"")
    assert elsewhere.requests == [] and len(engine.requests) == 1


def test_a_redirect_that_says_allow_is_not_an_allow(servers, monkeypatch):
    allow = json.dumps({"outcome": "allow", "decision_id": "01ABCDEFGHJKMNPQRSTVWXYZ00"})
    engine = servers(_Engine, [("answer", 302, [("Location", "/elsewhere")],
                               allow.encode())] * 2)
    monkeypatch.setenv("ARTZAIN_DECISION_URL", engine.url)
    assert sidecar.http_decide({"request_id": "r1"}) == {
        "outcome": "deny", "status_code": 503, "decision_id": ""}
    with pytest.raises(urllib.error.HTTPError) as raised:
        sidecar._post_engine(engine.url + "/api/v1/decisions", KEY, {}, retry_on_reset=False)
    assert raised.value.code == 302 and raised.value.headers["Location"] == "/elsewhere"
    assert json.loads(raised.value.read()) == json.loads(allow)
    assert [r["path"] for r in engine.requests] == ["/api/v1/decisions"] * 2


def test_the_path_and_query_reach_the_engine_as_written(servers):
    engine = servers(_Engine)
    client = _client(engine.url)
    _get(client, engine.url, "/api/v1/openshell/gateways/gw%2Fa/base-policy?x=1&y=%20")
    _get(client, engine.url, "")
    _get(client, engine.url, "?x=1")
    assert [r["path"] for r in engine.requests] == [
        "/api/v1/openshell/gateways/gw%2Fa/base-policy?x=1&y=%20", "/", "/?x=1"]
    assert engine.requests[0]["headers"]["X-Api-Key"] == KEY


# ---------------------------------------------------------------------------
# Connections that are kept
# ---------------------------------------------------------------------------


def test_a_second_request_uses_the_connection_the_first_one_opened(servers):
    engine = servers(_Engine)
    client = _client(engine.url)
    for _ in range(3):
        status, _headers, body = client.request(
            "POST", engine.url + "/api/v1/decisions", headers=HEADERS, body=b'{"a": 1}',
            deadline=_deadline())
        assert (status, body) == (200, b"{}")
    assert engine.connections == 1 and client.idle == 1
    assert [r["body"] for r in engine.requests] == [b'{"a": 1}'] * 3


def _read1_as_python_310(self, n=-1):
    """``HTTPResponse.read1`` as Python 3.10 has it. A body with a
    Content-Length, read to its end, leaves the response open: once
    ``length`` is 0 the read asks for 0 bytes, gets none, and does not close
    it. Python 3.11 closes it."""
    if self.fp is None or self._method == "HEAD":
        return b""
    if self.chunked:
        return self._read1_chunked(n)
    if self.length is not None and (n < 0 or n > self.length):
        n = self.length
    result = self.fp.read1(n)
    if not result and n:
        self._close_conn()
    elif self.length is not None:
        self.length -= len(result)
    return result


def test_a_kept_connection_is_used_again_where_read1_leaves_the_body_open(servers, monkeypatch):
    """On Python 3.10 every request after the first on a kept connection
    failed with ``ResponseNotReady('Request-sent')``: the previous answer,
    read to its end with ``read1``, was never closed, and ``http.client``
    will not read a new answer while an old one is open. The mirror's 3.10
    job found it; this suite runs on 3.11 here, so 3.10's ``read1`` is put
    in for the test."""
    monkeypatch.setattr(http.client.HTTPResponse, "read1", _read1_as_python_310)
    engine = servers(_Engine)
    client = _client(engine.url)
    for _ in range(3):
        status, _headers, body = client.request(
            "POST", engine.url + "/api/v1/decisions", headers=HEADERS, body=b'{"a": 1}',
            deadline=_deadline())
        assert (status, body) == (200, b"{}")
    assert engine.connections == 1 and client.idle == 1


def test_a_connection_the_engine_says_it_will_close_is_not_kept(servers):
    engine = servers(_Engine, ["close", "ok"])
    client = _client(engine.url)
    assert _get(client, engine.url)[0] == 200
    assert client.idle == 0
    assert _get(client, engine.url)[0] == 200
    assert engine.connections == 2


def test_a_kept_connection_the_engine_closed_is_not_used(servers):
    """The load balancer closes a connection it has not heard from. The next
    request must open a new one, not fail on the dead one: that request is
    not one that may be sent twice."""
    engine = servers(_Engine)
    client = _client(engine.url)
    assert _get(client, engine.url)[0] == 200
    engine.close_kept_connections()
    assert _get(client, engine.url, retry_on_reset=False)[0] == 200
    assert engine.connections == 2 and len(engine.requests) == 2


def test_a_connection_kept_too_long_is_not_used(servers):
    now = [1000.0]
    engine = servers(_Engine)
    client = transport.EngineClient(transport.Settings(*transport._origin(engine.url)),
                                    clock=lambda: now[0])
    _get(client, engine.url)
    now[0] += transport.IDLE_SECONDS
    _get(client, engine.url)
    assert engine.connections == 1  # at the limit it is still used
    now[0] += transport.IDLE_SECONDS + 0.1
    _get(client, engine.url)
    assert engine.connections == 2


def test_no_more_than_the_limit_is_kept(servers):
    engine = servers(_Engine, [("sleep", 0.3)] * 3)
    client = transport.EngineClient(transport.Settings(*transport._origin(engine.url)),
                                    max_idle=2)
    threads = [threading.Thread(target=_get, args=(client, engine.url)) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert engine.connections == 3 and client.idle == 2


def test_the_connection_used_last_is_the_one_used_next(servers):
    """The youngest kept connection is the least likely to have been closed
    by the far end, and using it lets the older ones age out."""
    engine = servers(_Engine, [("sleep", 0.4), "ok"])
    client = _client(engine.url)
    slow = threading.Thread(target=_get, args=(client, engine.url, "/slow"))
    slow.start()
    time.sleep(0.1)
    _get(client, engine.url, "/fast")   # kept first
    slow.join()                          # kept last
    assert client.idle == 2
    _get(client, engine.url, "/next")
    by_path = {r["path"]: r["port"] for r in engine.requests}
    assert by_path["/next"] == by_path["/slow"] != by_path["/fast"]


class _Socket:
    """A kept connection's socket, whose one read does what it is told."""

    def __init__(self, outcome):
        self.outcome, self.timeout = outcome, None

    def settimeout(self, value):
        self.timeout = value

    def recv(self, size):
        assert (size, self.timeout) == (1, 0)  # one byte, without waiting
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


@pytest.mark.parametrize("outcome, dropped", [
    (BlockingIOError(), False),            # nothing to read: still open
    (ssl.SSLWantReadError(), False),       # the same, said by TLS
    (InterruptedError(), False),
    (b"", True),                           # the far end closed it
    (b"H", True),                          # bytes nobody asked for
    (ConnectionResetError(), True),        # the far end reset it
    (ssl.SSLZeroReturnError(), True),
    (ssl.SSLEOFError(), True),
    (OSError("bad file descriptor"), True),
    (ValueError("closed"), True),
])
def test_how_a_kept_connection_is_found_dropped(outcome, dropped):
    class Kept:
        sock = _Socket(outcome)

    assert transport._dropped(Kept()) is dropped


def test_a_connection_with_no_socket_is_dropped():
    class Kept:
        sock = None

    assert transport._dropped(Kept()) is True


def test_a_closed_client_keeps_nothing(servers):
    engine = servers(_Engine)
    client = _client(engine.url)
    _get(client, engine.url)
    client.close()
    assert client.idle == 0
    _get(client, engine.url)  # still answers, on a connection it does not keep
    assert client.idle == 0 and engine.connections == 2


# ---------------------------------------------------------------------------
# Resets, deadlines and sizes
# ---------------------------------------------------------------------------


def test_a_reset_is_tried_once_more_only_when_asked(servers):
    engine = servers(_Engine, ["drop", "ok", "drop"])
    client = _client(engine.url)
    assert _get(client, engine.url, retry_on_reset=True)[0] == 200
    assert len(engine.requests) == 2

    with pytest.raises(Exception) as raised:
        _get(client, engine.url, retry_on_reset=False)
    assert transport.is_connection_reset(raised.value)
    assert len(engine.requests) == 3 and client.idle == 0


def test_a_second_reset_is_not_tried_again(servers):
    engine = servers(_Engine, ["drop", "drop", "ok"])
    with pytest.raises(Exception) as raised:
        _get(_client(engine.url), engine.url, retry_on_reset=True)
    assert transport.is_connection_reset(raised.value)
    assert len(engine.requests) == 2


@pytest.mark.parametrize("exc, reset", [
    (ConnectionResetError(), True), (BrokenPipeError(), True), (ConnectionAbortedError(), True),
    (ssl.SSLEOFError(), True), (ssl.SSLZeroReturnError(), True),
    (ConnectionRefusedError(), False), (TimeoutError(), False), (socket.timeout(), False),
    (ssl.SSLCertVerificationError(), False), (OSError("Tunnel connection failed"), False),
    (ValueError("engine answer too large"), False),
])
def test_what_counts_as_a_reset(exc, reset):
    assert transport.is_connection_reset(exc) is reset


def test_an_answer_that_is_late_is_not_waited_for(servers):
    engine = servers(_Engine, [("sleep", 2.0)])
    client = _client(engine.url)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        _get(client, engine.url, deadline=_deadline(0.3), retry_on_reset=True)
    assert time.monotonic() - started < 1.0
    assert len(engine.requests) == 1 and client.idle == 0  # a timeout is not tried again


def test_a_body_that_trickles_in_is_not_waited_for(servers):
    """The deadline is for the whole answer, not for each read of it."""
    engine = servers(_Engine, [("drip", 3.0), ("drip", 0.2)])
    client = _client(engine.url)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        _get(client, engine.url, deadline=_deadline(0.4))
    assert time.monotonic() - started < 1.5
    assert client.idle == 0
    status, _headers, body = _get(client, engine.url)  # a slow one inside its deadline
    assert status == 200 and json.loads(body) == {"a": "x" * 20}


def test_a_deadline_that_has_passed_sends_nothing(servers):
    engine = servers(_Engine)
    with pytest.raises(TimeoutError):
        _get(_client(engine.url), engine.url, deadline=time.monotonic() - 1)
    assert engine.connections == 0


def test_an_answer_that_is_too_large_is_refused(servers):
    big = b"x" * (transport.MAX_ANSWER_BYTES + 1)
    engine = servers(_Engine, [("answer", 200, [], big),
                               ("answer", 200, [], big[:-1])])
    client = _client(engine.url)
    with pytest.raises(ValueError, match="too large"):
        _get(client, engine.url, retry_on_reset=True)
    assert client.idle == 0
    assert len(engine.requests) == 1  # only a reset is tried again
    status, _headers, body = _get(client, engine.url)
    assert (status, len(body)) == (200, transport.MAX_ANSWER_BYTES)


def test_a_refusals_body_is_a_detail_and_its_status_stands(servers):
    big = b"x" * (transport.MAX_ANSWER_BYTES + 1)
    engine = servers(_Engine, [("answer", 429, [("Retry-After", "30")], big),
                               ("answer", 409, [], b'{"detail": "no"}')])
    client = _client(engine.url)
    status, headers, body = _get(client, engine.url)
    assert (status, headers["Retry-After"], body) == (429, "30", b"")
    assert client.idle == 0  # a body that was not read to its end ends the connection
    assert _get(client, engine.url)[::2] == (409, b'{"detail": "no"}')
    assert client.idle == 1


# ---------------------------------------------------------------------------
# The warm connection
# ---------------------------------------------------------------------------


def test_warm_opens_a_connection_and_the_next_request_uses_it(servers):
    engine = servers(_Engine)
    client = _client(engine.url)
    assert client.warm() is True
    assert (_connections(engine, 1), client.idle, engine.requests) == (1, 1, [])
    assert _get(client, engine.url)[0] == 200
    assert engine.connections == 1


def test_warm_renews_a_connection_that_has_waited_and_leaves_a_young_one(servers):
    now = [1000.0]
    engine = servers(_Engine)
    client = transport.EngineClient(transport.Settings(*transport._origin(engine.url)),
                                    clock=lambda: now[0])
    client.warm()
    now[0] += transport.RENEW_SECONDS
    assert client.warm() is True and _connections(engine, 1) == 1  # young enough
    now[0] += 0.1
    assert client.warm() is True
    assert (_connections(engine, 2), client.idle) == (2, 1)


def test_a_warm_connection_never_outlives_what_a_load_balancer_allows():
    # Renewed every 30 s once it is 25 s old, a waiting connection is at most
    # 55 s old when a request takes it, and one older than 50 s is not taken.
    assert transport.RENEW_SECONDS < transport.WARM_EVERY_SECONDS
    assert transport.IDLE_SECONDS < 60.0
    assert transport.WARM_EVERY_SECONDS <= transport.IDLE_SECONDS


def test_warm_on_an_engine_that_cannot_be_reached_does_not_raise():
    spare = socket.socket()
    spare.bind(("127.0.0.1", 0))
    port = spare.getsockname()[1]
    spare.close()
    client = _client("http://127.0.0.1:%d" % port)
    assert client.warm(timeout=1.0) is False and client.idle == 0


# ---------------------------------------------------------------------------
# The proxy
# ---------------------------------------------------------------------------


def test_a_request_goes_through_the_proxy_with_connect(servers):
    engine, proxy = servers(_Engine), servers(_Proxy)
    client = _client(engine.url, proxy=transport.Proxy("127.0.0.1", proxy.port))
    for _ in range(2):
        assert _get(client, engine.url)[0] == 200
    # One tunnel, kept. The HTTP version on the line is the interpreter's
    # (1.0 before Python 3.12, 1.1 since), and not this client's to choose.
    assert [line.rsplit(" ", 1)[0] for line, _headers in proxy.connects] == [
        "CONNECT 127.0.0.1:%d" % engine.port]
    assert len(engine.requests) == 2 and engine.connections == 1
    assert "proxy-authorization" not in proxy.connects[0][1]
    assert "x-api-key" not in proxy.connects[0][1]  # the key is the engine's, not the proxy's


def test_the_proxys_credentials_go_to_the_proxy_and_not_to_the_engine(servers):
    wanted = "Basic b3BzOnMzY3JldA=="
    engine, proxy = servers(_Engine), servers(_Proxy, require=wanted)
    client = _client(engine.url, proxy=transport.Proxy("127.0.0.1", proxy.port, wanted))
    assert _get(client, engine.url)[0] == 200
    assert proxy.connects[0][1]["proxy-authorization"] == wanted
    assert "Proxy-Authorization" not in engine.requests[0]["headers"]


def test_a_proxy_that_refuses_is_a_failure_and_the_engine_is_not_called_directly(servers):
    engine, proxy = servers(_Engine), servers(_Proxy, require="Basic bm9wZQ==")
    client = _client(engine.url, proxy=transport.Proxy("127.0.0.1", proxy.port))
    with pytest.raises(OSError, match="407"):
        _get(client, engine.url)
    assert engine.connections == 0 and client.warm(timeout=1.0) is False


def test_the_sidecar_goes_direct_whatever_the_environment_says_until_told(servers, monkeypatch):
    engine, proxy = servers(_Engine), servers(_Proxy)
    monkeypatch.setenv("http_proxy", proxy.url)
    monkeypatch.setenv("HTTP_PROXY", proxy.url)
    monkeypatch.setenv("ARTZAIN_DECISION_URL", engine.url)
    assert sidecar._post_engine(engine.url + "/api/v1/decisions", KEY, {},
                                retry_on_reset=False) == {}
    assert proxy.connects == []

    monkeypatch.setenv("OPENSHELL_SIDECAR_PROXY", "env")
    assert sidecar._post_engine(engine.url + "/api/v1/decisions", KEY, {},
                                retry_on_reset=False) == {}
    assert len(proxy.connects) == 1 and len(engine.requests) == 2


# ---------------------------------------------------------------------------
# TLS, under a certificate authority made for the test
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def authority(tmp_path_factory):
    """A certificate authority and what it signed: ``ca`` (its PEM file),
    ``good`` (a server context for 127.0.0.1) and ``other`` (one for another
    name)."""
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    folder = tmp_path_factory.mktemp("authority")
    now = datetime.datetime.now(datetime.timezone.utc)

    def name(common):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (x509.CertificateBuilder().subject_name(name("test authority"))
               .issuer_name(name("test authority")).public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=2))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=True, key_cert_sign=True, crl_sign=True,
                   content_commitment=False, key_encipherment=False,
                   data_encipherment=False, key_agreement=False, encipher_only=False,
                   decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                              critical=False)
               .sign(ca_key, hashes.SHA256()))
    ca_path = folder / "ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    def server_context(label, alternative_names):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(name(label))
                .issuer_name(ca_cert.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=2))
                .add_extension(x509.SubjectAlternativeName(alternative_names), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                               critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                               critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_key.public_key()), critical=False)
                .sign(ca_key, hashes.SHA256()))
        cert_path, key_path = folder / (label + ".pem"), folder / (label + ".key")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        return context

    return {
        "ca": str(ca_path),
        "good": server_context("good", [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
        "other": server_context("other", [x509.DNSName("engine.example")]),
    }


def test_an_engine_under_a_private_authority_needs_the_bundle(servers, authority):
    engine = servers(_Engine, tls=authority["good"])
    with pytest.raises(ssl.SSLCertVerificationError):
        _get(_client(engine.url), engine.url)
    assert engine.requests == []  # nothing was sent to an engine that was not verified

    client = _client(engine.url, ca_bundle=authority["ca"])
    assert _get(client, engine.url)[0] == 200
    assert engine.requests[0]["headers"]["X-Api-Key"] == KEY


def test_the_bundle_does_not_excuse_a_certificate_for_another_name(servers, authority):
    engine = servers(_Engine, tls=authority["other"])
    with pytest.raises(ssl.SSLCertVerificationError):
        _get(_client(engine.url, ca_bundle=authority["ca"]), engine.url)
    assert engine.requests == []


def test_a_warm_tls_connection_is_used_by_the_next_request(servers, authority):
    """After a TLS 1.3 handshake the engine sends session tickets nobody
    asked for. They must not make the waiting connection look closed."""
    engine = servers(_Engine, tls=authority["good"])
    client = _client(engine.url, ca_bundle=authority["ca"])
    assert client.warm() is True
    time.sleep(0.2)  # the tickets arrive
    for _ in range(2):
        assert _get(client, engine.url)[0] == 200
    assert engine.connections == 1


def test_a_kept_tls_connection_the_engine_closed_is_not_used(servers, authority):
    engine = servers(_Engine, tls=authority["good"])
    client = _client(engine.url, ca_bundle=authority["ca"])
    assert _get(client, engine.url)[0] == 200
    engine.close_kept_connections()
    assert _get(client, engine.url)[0] == 200
    assert engine.connections == 2


def test_through_a_proxy_the_tls_session_is_with_the_engine(servers, authority):
    engine, proxy = servers(_Engine, tls=authority["good"]), servers(_Proxy)
    client = _client(engine.url, ca_bundle=authority["ca"],
                     proxy=transport.Proxy("127.0.0.1", proxy.port))
    assert _get(client, engine.url)[0] == 200
    assert engine.requests[0]["headers"]["X-Api-Key"] == KEY
    # The proxy carried the session and could not read it.
    assert proxy.relayed and KEY.encode() not in bytes(proxy.relayed)


def test_the_sidecar_decides_through_a_proxy_and_a_private_authority(servers, authority,
                                                                      monkeypatch):
    allow = json.dumps({"outcome": "allow", "decision_id": "01ABCDEFGHJKMNPQRSTVWXYZ00"}).encode()
    engine = servers(_Engine, [("answer", 200, [], allow)], tls=authority["good"])
    proxy = servers(_Proxy)
    monkeypatch.setenv("ARTZAIN_DECISION_URL", engine.url)
    monkeypatch.setenv("OPENSHELL_SIDECAR_PROXY", proxy.url)
    monkeypatch.setenv("OPENSHELL_SIDECAR_CA_BUNDLE", authority["ca"])
    decision = sidecar.http_decide({"request_id": "r1", "action": "openshell_policy_change"})
    assert decision["outcome"] == "allow" and decision["status_code"] == 200
    assert len(proxy.connects) == 1
    assert engine.requests[0]["path"] == "/api/v1/decisions"


# ---------------------------------------------------------------------------
# The sidecar with settings it cannot honour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name, value", [
    ("OPENSHELL_SIDECAR_PROXY", "socks5://proxy.example:1080"),
    ("OPENSHELL_SIDECAR_CA_BUNDLE", "/nonexistent/ca.pem"),
])
def test_a_setting_that_cannot_be_honoured_denies_and_does_not_fall_back(
        servers, monkeypatch, name, value):
    engine = servers(_Engine)
    monkeypatch.setenv("ARTZAIN_DECISION_URL", engine.url)
    monkeypatch.setenv(name, value)
    assert sidecar.http_decide({"request_id": "r1"}) == {
        "outcome": "deny", "status_code": 503, "decision_id": ""}
    assert engine.connections == 0

    with pytest.raises(SystemExit) as stopped:
        sidecar.main()
    assert str(stopped.value).startswith("engine connection settings: " + name)


def test_the_sidecar_says_how_it_reaches_the_engine_and_no_credential(
        servers, monkeypatch, caplog):
    engine, proxy = servers(_Engine), servers(_Proxy)
    monkeypatch.setenv("ARTZAIN_DECISION_URL", engine.url)
    monkeypatch.setenv("OPENSHELL_SIDECAR_PROXY",
                       "http://ops:s3cret@127.0.0.1:%d" % proxy.port)

    class Stop(Exception):
        pass

    def no_server(*_args):
        raise Stop()

    monkeypatch.setattr(sidecar, "ThreadingHTTPServer", no_server)
    with caplog.at_level(logging.INFO), pytest.raises(Stop):
        sidecar.main()
    said = ('engine connection: {"engine": "http://127.0.0.1:%d", "proxy": "127.0.0.1:%d", '
            '"ca_bundle": false}' % (engine.port, proxy.port))
    assert said in caplog.text
    for secret in ("s3cret", "ops", "b3BzOnMzY3JldA", KEY):
        assert secret not in caplog.text
    # Started warm: the tunnel is up before the first write.
    assert len(proxy.connects) == 1 and _connections(engine, 1) == 1


def test_the_client_is_built_again_only_when_a_setting_changes(servers, monkeypatch):
    first, second = servers(_Engine), servers(_Engine)
    monkeypatch.setenv("ARTZAIN_DECISION_URL", first.url)
    client = sidecar._client()
    assert sidecar._client() is client
    assert sidecar.warm() is True and client.idle == 1

    monkeypatch.setenv("ARTZAIN_DECISION_URL", second.url + "/api/v1/decisions")
    other = sidecar._client()
    assert other is not client and other.settings.origin == ("http", "127.0.0.1", second.port)
    assert client.idle == 0  # the old one was closed

    monkeypatch.delenv("ARTZAIN_DECISION_URL")
    assert sidecar._client() is None and sidecar.warm() is False
    assert other.idle == 0


def test_after_a_bundle_that_could_not_be_loaded_the_client_is_a_new_one(
        servers, monkeypatch, tmp_path):
    engine = servers(_Engine)
    monkeypatch.setenv("ARTZAIN_DECISION_URL", engine.url.replace("http://", "https://"))
    not_pem = tmp_path / "ca.pem"
    not_pem.write_text("not a certificate")
    monkeypatch.setenv("OPENSHELL_SIDECAR_CA_BUNDLE", str(not_pem))
    for _ in range(2):
        with pytest.raises(transport.SettingsError):
            sidecar._client()

    monkeypatch.delenv("OPENSHELL_SIDECAR_CA_BUNDLE")
    monkeypatch.setenv("ARTZAIN_DECISION_URL", engine.url)
    first = sidecar._client()
    monkeypatch.setenv("ARTZAIN_DECISION_URL", engine.url.replace("http://", "https://"))
    monkeypatch.setenv("OPENSHELL_SIDECAR_CA_BUNDLE", str(not_pem))
    with pytest.raises(transport.SettingsError):
        sidecar._client()
    monkeypatch.delenv("OPENSHELL_SIDECAR_CA_BUNDLE")
    monkeypatch.setenv("ARTZAIN_DECISION_URL", engine.url)
    again = sidecar._client()
    assert again is not first  # the one closed on the way is not handed back
    assert sidecar.warm() is True and again.idle == 1


def test_a_settings_error_is_met_again_and_not_a_stale_client(servers, monkeypatch):
    engine = servers(_Engine)
    monkeypatch.setenv("ARTZAIN_DECISION_URL", engine.url)
    assert sidecar._client() is not None
    monkeypatch.setenv("OPENSHELL_SIDECAR_PROXY", "socks5://proxy.example:1080")
    for _ in range(2):
        with pytest.raises(transport.SettingsError):
            sidecar._client()
