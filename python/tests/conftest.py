"""Pytest fixtures shared by the artzain test suite.

Cloud ingest is exercised via :func:`artzain.cloud.post_sdk_event`; integration tests
patch ``urllib.request.urlopen`` to capture payloads without opening sockets.

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
    """Run :func:`artzain.cloud.post_sdk_event` HTTP delivery synchronously (tests only)."""

    import artzain.cloud as cloud

    class _SyncThread:
        def __init__(
            self,
            group=None,
            target=None,
            name=None,
            args=(),
            kwargs=None,
            *,
            daemon=None,
        ):
            self._target = target
            self._args = args if args else ()
            self._kwargs = kwargs if kwargs else {}

        def start(self) -> None:
            if self._target:
                self._target(*self._args, **self._kwargs)

    monkeypatch.setattr(cloud.threading, "Thread", _SyncThread)


@pytest.fixture
def artzain_events_capture(
    monkeypatch: pytest.MonkeyPatch,
    artzain_sync_cloud_threads: None,
) -> list[dict[str, Any]]:
    """Capture JSON bodies that would be POSTed to ``/api/events`` (no real network)."""

    import artzain.cloud as cloud

    captured: list[dict[str, Any]] = []

    class _Resp:
        status = 200

        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def read(self) -> bytes:
            return b"{}"

    def _fake_urlopen(req: Any, timeout: float | None = None) -> _Resp:
        data = getattr(req, "data", None)
        if data:
            try:
                captured.append(json.loads(data.decode("utf-8")))
            except json.JSONDecodeError:
                captured.append({"_raw": data.decode("utf-8", errors="replace")})
        return _Resp()

    monkeypatch.setattr(cloud.urllib.request, "urlopen", _fake_urlopen)

    return captured
