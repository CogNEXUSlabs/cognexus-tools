"""``decide()`` keeps its connection (decide-latency plan, step 3.1).

urllib asks for ``Connection: close`` and opens a new connection for every
request, so each decision paid the DNS lookup and the TCP and TLS handshakes
before its request: from Frankfurt, about 480 ms of a 690 ms decision. A
decision now goes on a kept connection, shared by the process's threads.

A request is sent again only when it cannot have reached the engine (sending
it failed on a kept connection), or when the caller's ``request_id`` makes the
engine answer a second copy with the first decision; never after a timeout.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import artzain.cloud as cloud
from artzain.decide import DecisionError, decide
from tests.test_openshell_transport import _Proxy, authority  # noqa: F401 - a fixture

KEY = "cnx_keep_alive_test_key"
ANSWER = {
    "outcome": "allow",
    "decision_id": "01J00000000000000000000000",
    "audit_block_id": "abc",
    "contributing_agents": [],
    "policy_bundle_version": "builtin:v0",
    "resolution_policy": "builtin/strict-v0",
    "latency_ms": 3,
    "reasons": [],
}


class _Engine:
    """A loopback Decision API that speaks HTTP/1.1 and keeps connections.

    ``script`` is a list of per-request behaviours: ``"ok"`` answers 200 with
    a decision; ``"close"`` answers, then closes the connection without
    saying so; ``"drop"`` reads the request and closes without answering;
    ``("sleep", s)`` answers after *s* seconds; ``("answer", status, raw,
    headers)`` answers exactly that.
    """

    def __init__(self, script=(), *, tls=None):
        self.script = list(script)
        self.requests = []
        self.connections = 0
        engine = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                return None

            def setup(self):
                super().setup()
                engine.connections += 1

            def _answer(self, status, raw, headers=()):
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):  # noqa: N802 - stdlib hook
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                engine.requests.append({"path": self.path, "body": json.loads(body),
                                        "headers": dict(self.headers.items()),
                                        "port": self.client_address[1]})
                step = engine.script.pop(0) if engine.script else "ok"
                if step == "drop":
                    self.close_connection = True
                    return
                if isinstance(step, tuple) and step[0] == "sleep":
                    time.sleep(step[1])
                    step = "ok"
                if step in ("ok", "close"):
                    self._answer(200, json.dumps(ANSWER).encode())
                    if step == "close":
                        self.close_connection = True
                    return
                _kind, status, raw, headers = step
                self._answer(status, raw, headers)

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False

        self.server = Server(("127.0.0.1", 0), Handler)
        if tls is not None:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.url = "%s://127.0.0.1:%d" % ("https" if tls is not None else "http", self.port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _close_kept():
    kept = getattr(cloud, "_KEPT", None)
    if kept is not None:
        kept.close()


@pytest.fixture
def engine(monkeypatch):
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.delenv("COGNEXUS_API_KEY", raising=False)
    _close_kept()
    made = []

    def start(script=(), **kwargs):
        eng = _Engine(script, **kwargs)
        made.append(eng)
        cloud.configure(api_key=KEY, base_url=eng.url)
        return eng

    yield start
    _close_kept()
    cloud.configure(api_key=None, base_url=None)
    for eng in made:
        eng.close()


def _decide(**kwargs):
    return decide(action="send_email", target="crm:1", payload="hello", **kwargs)


def _connections(eng, expected):
    """The connections the engine accepted, once its counting thread ran."""
    until = time.monotonic() + 2.0
    while eng.connections < expected and time.monotonic() < until:
        time.sleep(0.01)
    return eng.connections


def test_decisions_share_one_kept_connection(engine):
    eng = engine()
    for _ in range(3):
        assert _decide()["outcome"] == "allow"
    assert len(eng.requests) == 3
    assert _connections(eng, 1) == 1, "one TCP and TLS handshake, not one a decision"
    assert len({r["port"] for r in eng.requests}) == 1


def test_a_kept_decision_sends_what_it_sent_before(engine):
    eng = engine()
    _decide(request_id="r-1")
    [sent] = eng.requests
    headers = {name.lower(): value for name, value in sent["headers"].items()}
    assert sent["path"] == "/api/v1/decisions"
    assert headers["x-api-key"] == KEY
    assert headers["content-type"] == "application/json"
    assert headers["user-agent"].startswith("artzain-python-sdk/")
    assert headers.get("connection", "").lower() != "close"
    assert sent["body"]["request_id"] == "r-1" and sent["body"]["action"] == "send_email"


def test_threads_share_the_kept_connections(engine):
    eng = engine()
    outcomes, errors = [], []

    def work():
        try:
            for _ in range(3):
                outcomes.append(_decide()["outcome"])
        except Exception as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert errors == [] and outcomes == ["allow"] * 12
    assert eng.connections <= 4, "a connection for each thread at most, kept"


def test_a_connection_the_engine_closed_after_answering_is_not_used(engine):
    eng = engine(["close", "ok"])
    assert _decide()["outcome"] == "allow"
    time.sleep(0.2)  # the engine's close arrives
    assert _decide()["outcome"] == "allow"
    assert len(eng.requests) == 2 and _connections(eng, 2) == 2


def test_a_dropped_decision_is_not_sent_again_without_a_request_id(engine):
    eng = engine(["ok", "drop"])
    _decide()
    with pytest.raises(DecisionError, match="decision API unreachable"):
        _decide()
    assert len(eng.requests) == 2, "the engine may have sealed it: it is not sent twice"


def test_with_a_request_id_a_dropped_decision_is_asked_again_on_a_new_connection(engine):
    eng = engine(["ok", "drop", "ok"])
    _decide()
    assert _decide(request_id="r-2")["outcome"] == "allow"
    assert [r["body"]["request_id"] for r in eng.requests] == [None, "r-2", "r-2"]
    assert _connections(eng, 2) == 2


@pytest.mark.parametrize("request_id", ["", "   ", "a\x1fb"])
def test_a_request_id_the_engine_does_not_replay_is_not_asked_again(engine, request_id):
    # The engine strips a request_id, and replays none that is left empty or
    # holds U+001F: a second copy of such a decision would be sealed again.
    eng = engine(["ok", "drop"])
    _decide()
    with pytest.raises(DecisionError):
        _decide(request_id=request_id)
    assert len(eng.requests) == 2


def test_a_timeout_is_not_sent_again_even_with_a_request_id(engine):
    eng = engine(["ok", ("sleep", 1.5)])
    _decide()
    with pytest.raises(DecisionError, match="TimeoutError"):
        _decide(request_id="r-3", timeout_sec=0.5)
    assert len(eng.requests) == 2


def test_an_error_status_is_a_decision_error_and_the_connection_is_kept(engine):
    eng = engine([("answer", 503, b'{"detail": "audit_unavailable"}', ()), "ok"])
    with pytest.raises(DecisionError, match="HTTP 503: audit_unavailable") as raised:
        _decide()
    assert raised.value.status == 503
    assert _decide()["outcome"] == "allow"
    assert _connections(eng, 1) == 1


def test_a_redirect_is_not_followed(engine):
    eng = engine([("answer", 307, b"", (("Location", "http://other.invalid/api/v1/decisions"),))])
    with pytest.raises(DecisionError) as raised:
        _decide()
    assert raised.value.status == 307
    assert len(eng.requests) == 1


def test_changed_tls_settings_close_what_is_kept(engine, monkeypatch, tmp_path):
    eng = engine()
    _decide()
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "other.pem"))
    _decide()
    assert _connections(eng, 2) == 2


def test_a_connection_in_flight_when_the_settings_change_is_not_kept(engine, monkeypatch, tmp_path):
    engine([("sleep", 0.6), "ok"])
    slow = threading.Thread(target=_decide)
    slow.start()
    time.sleep(0.2)  # the slow decision is on its connection
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "other.pem"))
    _decide()
    slow.join(5)
    kept = [conn for pairs in cloud._KEPT._idle.values() for conn, _since in pairs]
    assert len(kept) == 1, "only the connection made under the settings now in force"


def test_a_child_process_does_not_use_its_parents_connections(engine, monkeypatch):
    eng = engine()
    _decide()
    parent = os.getpid()
    monkeypatch.setattr(cloud.os, "getpid", lambda: parent + 1)
    _decide()
    assert _connections(eng, 2) == 2


def test_an_http_url_a_proxy_would_carry_goes_through_urllib(engine, monkeypatch):
    eng = engine()
    monkeypatch.setenv("http_proxy", "http://proxy.invalid:3128")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    used = []

    class _Opener:
        def open(self, req, timeout=None):
            used.append(req.full_url)
            raise urllib.error.URLError(OSError("no proxy here"))

    monkeypatch.setattr(cloud, "_api_opener", lambda: _Opener())
    with pytest.raises(DecisionError):
        _decide()
    assert used == [eng.url + "/api/v1/decisions"] and eng.requests == []


def test_a_request_no_one_marked_goes_through_urllib(engine, monkeypatch):
    eng = engine()
    import urllib.request

    req = urllib.request.Request(eng.url + "/api/v1/decisions", data=b"{}", method="POST")
    used = []
    monkeypatch.setattr(cloud, "_api_opener", lambda: type(
        "_Opener", (), {"open": lambda self, r, timeout=None: used.append(r) or "urllib"})())
    assert cloud._urlopen(req, timeout=1.0) == "urllib" and used == [req]


# ---------------------------------------------------------------------------
# TLS and the proxy
# ---------------------------------------------------------------------------


def test_a_decision_over_tls_keeps_its_connection(engine, authority, monkeypatch):  # noqa: F811
    monkeypatch.setenv("SSL_CERT_FILE", authority["ca"])
    eng = engine(tls=authority["good"])
    for _ in range(2):
        assert _decide()["outcome"] == "allow"
    assert _connections(eng, 1) == 1


def test_a_certificate_for_another_name_is_refused(engine, authority, monkeypatch):  # noqa: F811
    monkeypatch.setenv("SSL_CERT_FILE", authority["ca"])
    eng = engine(tls=authority["other"])
    with pytest.raises(DecisionError, match="SSLCertVerificationError"):
        _decide()
    assert eng.requests == []


def test_a_decision_over_tls_goes_through_the_proxy_and_keeps_the_tunnel(
        engine, authority, monkeypatch):  # noqa: F811
    monkeypatch.setenv("SSL_CERT_FILE", authority["ca"])
    eng = engine(tls=authority["good"])
    proxy = _Proxy()
    monkeypatch.setenv("https_proxy", proxy.url)
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    for _ in range(2):
        assert _decide()["outcome"] == "allow"
    assert [line.rsplit(" ", 1)[0] for line, _headers in proxy.connects] == [
        "CONNECT 127.0.0.1:%d" % eng.port]
    assert len(eng.requests) == 2 and _connections(eng, 1) == 1
    assert "x-api-key" not in proxy.connects[0][1], "the key is the engine's, not the proxy's"
