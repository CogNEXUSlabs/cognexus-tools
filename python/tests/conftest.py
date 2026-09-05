"""Pytest fixtures shared by the artzain test suite.

Cloud ingest is exercised via :func:`artzain.cloud.post_sdk_event`; integration tests
patch the ``http.client`` connection classes to capture payloads without opening
sockets.

Run integration tests::

    cd pypi-package
    export PYTHONPATH=src
    export COGNEXUS_API_KEY="your-key"
    python -m pytest tests/test_api_key_integration.py -v
"""

from __future__ import annotations

import json
from typing import Any

import pytest


@pytest.fixture
def artzain_sync_cloud_threads(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run :func:`artzain.cloud.post_sdk_event` HTTP delivery synchronously (tests only).

    Bypasses the background worker queue: each queued POST is delivered inline
    on the calling thread through a private transport.
    """

    import artzain.cloud as cloud

    transport = cloud._CloudTransport()

    def _deliver_inline(item: cloud._QueuedPost) -> bool:
        cloud._deliver_post(transport, item)
        return True

    monkeypatch.setattr(cloud, "_enqueue_post", _deliver_inline)


@pytest.fixture
def artzain_fresh_cloud_worker(monkeypatch: pytest.MonkeyPatch):
    """A private :class:`artzain.cloud._CloudWorker` for tests that exercise the queue.

    The module singleton is swapped for the duration of the test and the
    private worker is drained and stopped on teardown.
    """

    import artzain.cloud as cloud

    worker = cloud._CloudWorker()
    monkeypatch.setattr(cloud, "_worker", worker)
    try:
        yield worker
    finally:
        worker.close(timeout_sec=5.0)


class _FakeHTTPResponse:
    def __init__(self, status: int = 200, body: bytes = b"{}") -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body


def install_fake_http_connections(
    monkeypatch: pytest.MonkeyPatch,
    captured: list[dict[str, Any]],
    *,
    on_request: Any = None,
    status: int = 200,
) -> list[Any]:
    """Replace ``http.client`` connection classes in :mod:`artzain.cloud` with fakes.

    Every JSON body sent through ``request()`` is appended to *captured*;
    *on_request* (if given) is called first with ``(method, path, body)`` and may
    raise or block to simulate failures / slow servers. Returns the list of fake
    connection instances constructed so tests can count them.
    """

    import artzain.cloud as cloud

    instances: list[Any] = []

    class _FakeConnection:
        def __init__(self, host: str, port: int | None = None, *, timeout: Any = None, **kw: Any) -> None:
            self.host = host
            self.port = port
            self.timeout = timeout
            self.closed = 0
            instances.append(self)

        def set_tunnel(self, host: str, port: int | None = None, headers: Any = None) -> None:
            self.tunnel = (host, port)
            self.tunnel_headers = dict(headers or {})

        def request(self, method: str, path: str, body: Any = None, headers: Any = None) -> None:
            if on_request is not None:
                on_request(method, path, body)
            if body:
                try:
                    captured.append(json.loads(body.decode("utf-8")))
                except json.JSONDecodeError:
                    captured.append({"_raw": body.decode("utf-8", errors="replace")})

        def getresponse(self) -> _FakeHTTPResponse:
            return _FakeHTTPResponse(status=status)

        def close(self) -> None:
            self.closed += 1

    monkeypatch.setattr(cloud.http.client, "HTTPSConnection", _FakeConnection)
    monkeypatch.setattr(cloud.http.client, "HTTPConnection", _FakeConnection)
    return instances


@pytest.fixture
def artzain_events_capture(
    monkeypatch: pytest.MonkeyPatch,
    artzain_sync_cloud_threads: None,
) -> list[dict[str, Any]]:
    """Capture JSON bodies that would be POSTed to ``/api/events`` (no real network)."""

    captured: list[dict[str, Any]] = []
    install_fake_http_connections(monkeypatch, captured)
    return captured
