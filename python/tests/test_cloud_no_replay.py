"""A telemetry POST is sent once: never again after the server may have read it
(survey 25 Sep 2026, row 35).

The event and human-decision posts go over one kept-alive connection. Any
failure on a reused connection was retried on a fresh one, a read timeout
included, so a slow answer stored the event (or an approve/deny verdict) twice
with nothing to tell the copies apart. A request is now sent again only when
it did not get out whole. A connection the server closed while idle, or one
idle long enough for a NAT on the way to have forgotten it, is replaced before
anything is sent on it.
"""

from __future__ import annotations

import http.server
import select
import socket
import struct
import threading
import time

import pytest

import artzain.cloud as cloud

TIMEOUT = 1.0
SLOW = 2.5


class _Server:
    """A local HTTP/1.1 server that keeps connections alive and records every
    request body it has read in full, whatever it does next."""

    def __init__(self, behaviour):
        self.bodies: list[bytes] = []
        self.connections = 0
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                outer.connections += 1
                super().setup()

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.bodies.append(body)
                action = behaviour(body)
                if action == "drop":
                    # Read, perhaps acted on, and the connection closed unanswered.
                    self.close_connection = True
                    return
                if action == "slow":
                    time.sleep(SLOW)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
                self.wfile.flush()
                if action == "close_after":
                    # An idle timeout: closed after the answer, no Connection: close.
                    self.close_connection = True
                elif action == "forgotten_after":
                    # A NAT that forgot the idle flow: nothing reaches the
                    # client until it sends, and what it sends is answered
                    # with a reset, never read.
                    self.close_connection = True
                    readable, _, _ = select.select([self.connection], [], [], 5.0)
                    if readable:
                        self.connection.setsockopt(
                            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    self.connection.close()

            def log_message(self, *args):
                pass

        class _Quiet(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass  # an answer to a socket the client has closed, a reset

        self.httpd = _Quiet(("127.0.0.1", 0), _Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/api/events"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def serve():
    started: list[_Server] = []

    def _start(behaviour):
        server = _Server(behaviour)
        started.append(server)
        return server

    yield _start
    for server in started:
        server.stop()


@pytest.fixture
def transport():
    t = cloud._CloudTransport()
    yield t
    t.close()


def _post(transport, server, body: bytes):
    return transport.post(server.url, body, {"Content-Type": "application/json"}, TIMEOUT)


def test_a_slow_answer_on_a_kept_alive_connection_is_not_asked_for_again(serve, transport):
    server = serve(lambda body: "slow" if body == b'{"n":2}' else "ok")
    assert _post(transport, server, b'{"n":1}')[0] == 200
    with pytest.raises(OSError):
        _post(transport, server, b'{"n":2}')
    time.sleep(0.2)
    assert server.bodies == [b'{"n":1}', b'{"n":2}']


def test_a_request_the_server_read_and_left_unanswered_is_not_sent_again(serve, transport):
    server = serve(lambda body: "drop" if body == b'{"n":2}' else "ok")
    assert _post(transport, server, b'{"n":1}')[0] == 200
    with pytest.raises(OSError):
        _post(transport, server, b'{"n":2}')
    time.sleep(0.2)
    assert server.bodies == [b'{"n":1}', b'{"n":2}']


def test_a_connection_the_server_closed_while_idle_is_replaced_and_the_post_goes_once(
        serve, transport):
    server = serve(lambda body: "close_after" if body == b'{"n":1}' else "ok")
    assert _post(transport, server, b'{"n":1}')[0] == 200
    time.sleep(0.3)  # the server's close reaches the client
    assert _post(transport, server, b'{"n":2}')[0] == 200
    assert _post(transport, server, b'{"n":3}')[0] == 200
    assert server.bodies == [b'{"n":1}', b'{"n":2}', b'{"n":3}']
    assert server.connections == 2


def test_a_post_that_goes_out_in_one_piece_is_not_sent_on_a_closed_connection(
        serve, transport, monkeypatch):
    # With no body, headers are the whole request and one send takes them
    # all, so the send itself cannot fail on a closed connection: only the
    # check before it keeps the post from being lost.
    server = serve(lambda body: "close_after" if body == b'{"n":1}' else "ok")
    assert _post(transport, server, b'{"n":1}')[0] == 200
    time.sleep(0.3)
    sends: list = []
    real_request = cloud.http.client.HTTPConnection.request

    def _counted(self, *args, **kwargs):
        sends.append(args)
        return real_request(self, *args, **kwargs)

    monkeypatch.setattr(cloud.http.client.HTTPConnection, "request", _counted)
    assert _post(transport, server, b"")[0] == 200
    assert len(sends) == 1
    assert server.bodies == [b'{"n":1}', b""]


def test_a_connection_idle_past_what_a_nat_keeps_is_replaced_before_sending(
        serve, transport):
    # A NAT or firewall that drops an idle flow tells neither end: the
    # connection looks open until a post goes out on it and is reset. One
    # idle that long is not used again.
    server = serve(lambda body: "forgotten_after" if body == b'{"n":1}' else "ok")
    assert _post(transport, server, b'{"n":1}')[0] == 200
    time.sleep(0.2)
    transport._idle_since -= cloud._CONNECTION_IDLE_LIMIT_SEC + 1  # a long lull
    assert _post(transport, server, b'{"n":2}')[0] == 200
    assert server.bodies == [b'{"n":1}', b'{"n":2}']
    assert server.connections == 2


def test_a_connection_used_again_soon_is_kept(serve, transport):
    server = serve(lambda body: "ok")
    for n in range(3):
        assert _post(transport, server, b'{"n":%d}' % n)[0] == 200
    assert server.connections == 1


@pytest.mark.parametrize(("failure", "sent_twice"), [
    (BrokenPipeError("the server went away mid-send"), True),
    (TimeoutError("the server stopped reading"), False),
])
def test_a_send_that_fails_on_a_kept_alive_connection(monkeypatch, failure, sent_twice):
    # A send that failed on a closed connection did not get out whole, so the
    # server cannot have acted on it: one more try on a fresh connection. One
    # that timed out met a slow server, not a closed connection.
    idle_a, idle_b = socket.socketpair()
    sent: list[tuple[int, bytes]] = []
    opened: list = []

    class _Response:
        status = 200

        def read(self):
            return b"{}"

    class _Conn:
        def __init__(self, *args, **kwargs):
            self.index = len(opened)
            self.sock = None
            self.uses = 0
            opened.append(self)

        def request(self, method, path, body=None, headers=None):
            self.uses += 1
            if self.index == 0 and self.uses == 2:
                raise failure
            sent.append((self.index, body))
            self.sock = idle_a  # kept alive, nothing to read

        def getresponse(self):
            return _Response()

        def close(self):
            self.sock = None

    monkeypatch.setattr(cloud.http.client, "HTTPConnection", _Conn)
    transport = cloud._CloudTransport()
    try:
        assert transport.post("http://127.0.0.1:1/api/events", b"one", {}, TIMEOUT)[0] == 200
        if sent_twice:
            assert transport.post("http://127.0.0.1:1/api/events", b"two", {}, TIMEOUT)[0] == 200
        else:
            with pytest.raises(TimeoutError):
                transport.post("http://127.0.0.1:1/api/events", b"two", {}, TIMEOUT)
    finally:
        idle_a.close()
        idle_b.close()
    assert sent == ([(0, b"one"), (1, b"two")] if sent_twice else [(0, b"one")])
    assert len(opened) == (2 if sent_twice else 1)
