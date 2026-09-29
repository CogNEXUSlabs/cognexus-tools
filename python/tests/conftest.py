"""Pytest fixtures shared by the artzain test suite.

Cloud ingest is exercised via :func:`artzain.cloud.post_sdk_event`; integration tests
patch the ``http.client`` connection classes to capture payloads without opening
sockets.

Run integration tests::

    cd pypi-package
    export PYTHONPATH=src
    export COGNEXUS_API_KEY="your-key"
    python -m pytest tests/test_api_key_integration.py -v

That module reads the key when it is imported. The rest of the session runs
with the key variables cleared (``_no_ambient_api_key``), so the key may stay
exported for the whole suite.
"""

from __future__ import annotations

import json
import os
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def _restore_cloud_configure():
    """``configure()`` is process-wide; a test that sets it must not pass it on.

    Since the host is resolved together with the key, a key one test
    configured and left behind changes which host the next test's key goes to.
    """
    import artzain.cloud as cloud

    saved = (cloud._override_key, cloud._override_base)
    yield
    cloud._override_key, cloud._override_base = saved


@pytest.fixture(autouse=True)
def _no_ambient_policy_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    """Offline ``decide()`` and ``screen_client_policy()`` screen the rules the
    environment configures, and a list that loads is cached for the process: a
    developer's ``COGNEXUS_POLICY_RULES_*`` must not reach the suite, nor one
    test's rules the next test."""
    monkeypatch.delenv("COGNEXUS_POLICY_RULES_JSON", raising=False)
    monkeypatch.delenv("COGNEXUS_POLICY_RULES_PATH", raising=False)
    from artzain import _helpers

    monkeypatch.setattr(_helpers, "_policy_rules_cache", None)


@pytest.fixture(autouse=True)
def _no_ambient_credentials_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """The developer's own credentials profile must not reach the suite.

    When neither ``configure()`` nor the environment sets a key, ``decide()``,
    the event posts and the other calls to the API use the key in the
    credentials profile, so on a machine that ran ``artzain login`` a test
    meant to run without a key would send its payload to the API under that
    key; and a profile held by another program refuses every request. Each
    test gets a profile path of its own that names a file that does not
    exist, in place of ``~/.artzain/credentials.toml`` or the file a
    developer's ``COGNEXUS_CREDENTIALS_PATH`` names; a test that wants a
    profile sets ``COGNEXUS_CREDENTIALS_PATH`` itself. A credential conflict
    is warned of once per process, so each test starts with none warned of."""
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp_path / "no-credentials-profile.toml"))
    from artzain import cloud

    monkeypatch.setattr(cloud, "_conflicts_warned", set())


#: What a developer's shell may export for the integration tests.
_KEY_VARIABLES = ("COGNEXUS_API_KEY", "MYAPP_API_KEY", "COGNEXUS_API_BASE_URL")


@pytest.fixture(autouse=True, scope="session")
def _no_ambient_api_key():
    """A key exported in the shell must not reach the suite either. The one a
    developer exports for the integration tests (see above) stays exported
    for the rest of the suite, and code that did not clear it would send its
    events under that key, to the host ``COGNEXUS_API_BASE_URL`` names or,
    with that unset, to the default host, the production API. The session
    runs with ``COGNEXUS_API_KEY``, ``MYAPP_API_KEY`` and
    ``COGNEXUS_API_BASE_URL`` unset from before this suite's module-, class-
    and function-scoped fixtures, so those fixtures and ``setUpClass`` do not
    see them either; the values the shell exported are put back when the
    session ends. An event post resolves its key when it queues the row, so
    no row is left for the flush at interpreter exit. Code that runs before
    any test's fixtures are set up (at import, during collection, or in a
    ``skipif`` string) or after the session still sees them:
    ``test_api_key_integration.py`` reads its key at import."""
    with pytest.MonkeyPatch.context() as mp:
        for name in _KEY_VARIABLES:
            mp.delenv(name, raising=False)
        yield


@pytest.fixture(autouse=True)
def _no_api_key_left_by_a_test():
    """Each test leaves them as it found them. Code under test may put one in
    ``os.environ`` itself, as ``artzain login`` does, and the tests after it
    must not see it; one that module- or class-scoped setup put there for its
    tests stays. A test that wants one sets it itself."""
    found = {name: os.environ.get(name) for name in _KEY_VARIABLES}
    yield
    for name, value in found.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


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
