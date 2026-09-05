"""Tests for optional dashboard ingest (no network when no key)."""

import io
import threading
import time
import urllib.error

import artzain.cloud as cloud
from artzain.cloud import (
    announce_cloud_ingest,
    configure,
    fetch_api_key_identity,
    flush_cloud_events,
    post_sdk_event,
)
from tests.conftest import install_fake_http_connections


def test_post_sdk_event_no_key_no_crash():
    configure(api_key=None, base_url=None)
    post_sdk_event("unit_test", payload={"ok": True})


def test_configure_override(monkeypatch):
    monkeypatch.delenv("COGNEXUS_API_KEY", raising=False)
    monkeypatch.delenv("MYAPP_API_KEY", raising=False)
    monkeypatch.delenv("COGNEXUS_API_BASE_URL", raising=False)
    configure(api_key="k", base_url="https://example.com")
    assert cloud._effective_key() == "k"
    assert cloud._effective_base() == "https://example.com"
    configure(api_key=None, base_url=None)
    assert cloud._effective_key() is None
    assert cloud._effective_base() == "https://app.cognexuslabs.ai"


def _quiet_session(monkeypatch):
    """Skip the once-per-process ``sdk_session`` row so event counts are exact."""
    monkeypatch.setattr(cloud, "_session_logged", True)


def test_flush_cloud_events_waits_for_background_post(
    monkeypatch, artzain_fresh_cloud_worker
):
    configure(api_key="unit-key", base_url="https://example.com")
    _quiet_session(monkeypatch)
    done = threading.Event()
    captured: list = []

    def _slow(method, path, body):
        time.sleep(0.05)
        done.set()

    install_fake_http_connections(monkeypatch, captured, on_request=_slow)
    post_sdk_event("flush_test", payload={"n": 1})
    assert not done.is_set()
    flush_cloud_events(timeout_sec=2.0)
    assert done.is_set()
    assert [b["event_type"] for b in captured] == ["flush_test"]


def test_post_sdk_event_uses_one_worker_thread(monkeypatch, artzain_fresh_cloud_worker):
    """500 events start at most one background thread (not one per event)."""
    configure(api_key="unit-key", base_url="https://example.com")
    _quiet_session(monkeypatch)
    captured: list = []
    install_fake_http_connections(monkeypatch, captured)

    real_thread = threading.Thread
    started: list = []

    class _CountingThread(real_thread):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            started.append(self)

    monkeypatch.setattr(cloud.threading, "Thread", _CountingThread)
    for i in range(500):
        post_sdk_event("burst", payload={"i": i})
    assert flush_cloud_events(timeout_sec=10.0) is None
    assert len(started) <= 1, f"expected one worker thread, got {len(started)}"
    assert len(captured) == 500
    assert cloud.dropped_cloud_events() == 0


def test_connection_is_reused_across_events(monkeypatch, artzain_fresh_cloud_worker):
    """One HTTPSConnection serves every queued event instead of one per POST."""
    configure(api_key="unit-key", base_url="https://example.com")
    _quiet_session(monkeypatch)
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    captured: list = []
    instances = install_fake_http_connections(monkeypatch, captured)
    for i in range(50):
        post_sdk_event("reuse", payload={"i": i})
    flush_cloud_events(timeout_sec=10.0)
    assert len(captured) == 50
    assert len(instances) == 1
    assert instances[0].host == "example.com"
    assert instances[0].closed == 0


def test_transport_tunnels_through_https_proxy(monkeypatch, artzain_fresh_cloud_worker):
    """``HTTPS_PROXY`` is honoured (urlopen did this implicitly)."""
    configure(api_key="unit-key", base_url="https://example.com")
    _quiet_session(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.local:3128")
    monkeypatch.setenv("https_proxy", "http://proxy.local:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    captured: list = []
    instances = install_fake_http_connections(monkeypatch, captured)
    post_sdk_event("via_proxy", payload={"n": 1})
    flush_cloud_events(timeout_sec=5.0)
    assert len(captured) == 1
    assert (instances[0].host, instances[0].port) == ("proxy.local", 3128)
    assert instances[0].tunnel == ("example.com", None)
    assert instances[0].tunnel_headers == {}


def test_transport_forwards_proxy_credentials(monkeypatch, artzain_fresh_cloud_worker):
    configure(api_key="unit-key", base_url="https://example.com")
    _quiet_session(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "http://user:p%40ss@proxy.local:3128")
    monkeypatch.setenv("https_proxy", "http://user:p%40ss@proxy.local:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    captured: list = []
    instances = install_fake_http_connections(monkeypatch, captured)
    post_sdk_event("via_auth_proxy", payload={"n": 1})
    flush_cloud_events(timeout_sec=5.0)
    assert len(captured) == 1
    assert instances[0].host == "proxy.local"
    # base64("user:p@ss")
    assert instances[0].tunnel_headers == {"Proxy-Authorization": "Basic dXNlcjpwQHNz"}


def test_full_queue_drops_and_counts_without_blocking(monkeypatch):
    """A saturated queue drops new events (counted) rather than blocking the caller."""
    configure(api_key="unit-key", base_url="https://example.com")
    _quiet_session(monkeypatch)
    worker = cloud._CloudWorker(maxsize=3)
    monkeypatch.setattr(cloud, "_worker", worker)
    release = threading.Event()
    captured: list = []

    def _block(method, path, body):
        release.wait(5.0)

    install_fake_http_connections(monkeypatch, captured, on_request=_block)
    try:
        t0 = time.monotonic()
        for i in range(20):
            post_sdk_event("flood", payload={"i": i})
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0, f"post_sdk_event blocked for {elapsed:.2f}s"
        # Three slots plus at most one in flight; everything else is dropped.
        assert worker.dropped >= 16
        assert cloud.dropped_cloud_events() == worker.dropped
    finally:
        release.set()
        worker.close(timeout_sec=5.0)
    assert len(captured) + worker.dropped == 20


def test_failing_send_does_not_raise(monkeypatch, artzain_fresh_cloud_worker, caplog):
    configure(api_key="unit-key", base_url="https://example.com")
    _quiet_session(monkeypatch)
    captured: list = []

    def _boom(method, path, body):
        raise OSError("connection reset")

    install_fake_http_connections(monkeypatch, captured, on_request=_boom)
    with caplog.at_level("WARNING", logger="artzain.cloud"):
        post_sdk_event("will_fail", payload={"n": 1})
        flush_cloud_events(timeout_sec=5.0)
    assert captured == []
    assert any("will_fail" in r.getMessage() for r in caplog.records)


def test_transport_reconnects_after_error(monkeypatch, artzain_fresh_cloud_worker):
    """After a failed send the connection is closed; the next event still goes out."""
    configure(api_key="unit-key", base_url="https://example.com")
    _quiet_session(monkeypatch)
    captured: list = []
    calls = {"n": 0}

    def _first_fails(method, path, body):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionResetError("stale keep-alive")

    instances = install_fake_http_connections(monkeypatch, captured, on_request=_first_fails)
    post_sdk_event("first", payload={"n": 1})
    post_sdk_event("second", payload={"n": 2})
    flush_cloud_events(timeout_sec=5.0)
    assert [b["event_type"] for b in captured] == ["second"]
    assert instances[0].closed >= 1


def test_flush_drains_queue(monkeypatch, artzain_fresh_cloud_worker):
    configure(api_key="unit-key", base_url="https://example.com")
    _quiet_session(monkeypatch)
    captured: list = []
    install_fake_http_connections(
        monkeypatch, captured, on_request=lambda *a: time.sleep(0.002)
    )
    for i in range(25):
        post_sdk_event("drain", payload={"i": i})
    assert artzain_fresh_cloud_worker.flush(timeout_sec=5.0) is True
    assert len(captured) == 25


def test_flush_times_out_when_send_stalls(monkeypatch):
    configure(api_key="unit-key", base_url="https://example.com")
    _quiet_session(monkeypatch)
    worker = cloud._CloudWorker()
    monkeypatch.setattr(cloud, "_worker", worker)
    release = threading.Event()
    captured: list = []
    install_fake_http_connections(
        monkeypatch, captured, on_request=lambda *a: release.wait(5.0)
    )
    try:
        post_sdk_event("stall", payload={"n": 1})
        assert worker.flush(timeout_sec=0.1) is False
    finally:
        release.set()
        worker.close(timeout_sec=5.0)


def test_fetch_api_key_identity_valid(monkeypatch):
    configure(api_key="cnx_testkey1234567890", base_url="https://example.com")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def read(self):
            return (
                b'{"ok":true,"email":"dev@example.com","display_name":"Dev User",'
                b'"key_prefix":"cnx_testkey12","key_label":"quickstart"}'
            )

    monkeypatch.setattr(cloud.urllib.request, "urlopen", lambda *a, **k: _Resp())
    info = fetch_api_key_identity()
    assert info["valid"] is True
    assert info["email"] == "dev@example.com"
    assert info["display_name"] == "Dev User"
    assert info["key_prefix"] == "cnx_testkey12"
    assert info["key_label"] == "quickstart"


def test_fetch_api_key_identity_no_key(monkeypatch):
    monkeypatch.delenv("COGNEXUS_API_KEY", raising=False)
    monkeypatch.delenv("MYAPP_API_KEY", raising=False)
    configure(api_key=None, base_url=None)
    info = fetch_api_key_identity()
    assert info["valid"] is False
    assert info["error"] == "no_api_key"


def test_fetch_api_key_identity_falls_back_on_405(monkeypatch):
    configure(api_key="cnx_testkey1234567890", base_url="https://example.com")

    class _Events200:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def read(self):
            return b'{"ok":true}'

    def _urlopen(req, timeout=None):
        if getattr(req, "method", None) == "GET":
            raise urllib.error.HTTPError(
                req.full_url,
                405,
                "Method Not Allowed",
                {},
                None,
            )
        return _Events200()

    monkeypatch.setattr(cloud.urllib.request, "urlopen", _urlopen)
    info = fetch_api_key_identity()
    assert info["valid"] is True
    assert info["verified_via"] == "events"
    assert info["email"] == ""


def test_announce_cloud_ingest_valid_via_events_probe(monkeypatch):
    configure(api_key="cnx_testkey1234567890", base_url="https://example.com")
    monkeypatch.setattr(
        cloud,
        "fetch_api_key_identity",
        lambda **k: {
            "valid": True,
            "email": "",
            "display_name": "",
            "key_prefix": "cnx_testkey12",
            "key_label": "",
            "base_url": "https://example.com",
            "verified_via": "events",
        },
    )
    buf = io.StringIO()
    assert announce_cloud_ingest(file=buf) is True
    text = buf.getvalue()
    assert "valid" in text
    assert "enabled" in text
    assert "email lookup unavailable" in text


def test_announce_cloud_ingest_valid(monkeypatch):
    configure(api_key="cnx_testkey1234567890", base_url="https://example.com")
    monkeypatch.setattr(
        cloud,
        "fetch_api_key_identity",
        lambda **k: {
            "valid": True,
            "email": "dev@example.com",
            "display_name": "Dev User",
            "key_prefix": "cnx_testkey12",
            "key_label": "demo",
            "base_url": "https://example.com",
        },
    )
    buf = io.StringIO()
    assert announce_cloud_ingest(file=buf) is True
    text = buf.getvalue()
    assert "valid" in text
    assert "dev@example.com" in text
    assert "Event Logs" in text


def test_announce_cloud_ingest_missing_key(monkeypatch):
    monkeypatch.delenv("COGNEXUS_API_KEY", raising=False)
    monkeypatch.delenv("MYAPP_API_KEY", raising=False)
    configure(api_key=None, base_url=None)
    buf = io.StringIO()
    assert announce_cloud_ingest(file=buf) is False
    assert "not set" in buf.getvalue()


def test_key_hint_masks_keys_too_short_to_truncate():
    assert cloud._key_hint("cnx_testkey1234567890") == "cnx_testkey123…"
    assert cloud._key_hint("short") == "redacted"
    assert cloud._key_hint("") == "redacted"
    # Exactly `keep` characters still has nothing to spare.
    assert cloud._key_hint("0123456789abcd") == "redacted"
    assert cloud._key_hint("cnx_test", keep=4) == "cnx_…"


def test_announce_cloud_ingest_never_echoes_a_short_key(monkeypatch):
    """A malformed key must not reach stdout in full when validation fails."""
    configure(api_key="cnx_bad", base_url="https://example.com")
    monkeypatch.setattr(
        cloud,
        "fetch_api_key_identity",
        lambda **k: {"valid": False, "error": "invalid_or_revoked"},
    )
    buf = io.StringIO()
    assert announce_cloud_ingest(file=buf) is False
    text = buf.getvalue()
    assert "cnx_bad" not in text
    assert "redacted" in text


def test_announce_cloud_ingest_falls_back_to_local_prefix(monkeypatch):
    """With no server-supplied prefix, the local hint is still truncated."""
    configure(api_key="cnx_testkey1234567890", base_url="https://example.com")
    monkeypatch.setattr(
        cloud,
        "fetch_api_key_identity",
        lambda **k: {"valid": True, "email": "", "display_name": "", "key_prefix": ""},
    )
    buf = io.StringIO()
    assert announce_cloud_ingest(file=buf) is True
    text = buf.getvalue()
    assert "cnx_testkey123…" in text
    assert "cnx_testkey1234567890" not in text


def test_401_warning_names_the_base_url_source_not_the_url(monkeypatch, caplog):
    """The base URL can come from the credentials profile, which is the file
    that also holds the API key, so a log line must not be built from it."""
    from artzain import cloud

    monkeypatch.setenv("COGNEXUS_API_BASE_URL", "https://tenant-secret.example.test")
    monkeypatch.setattr(cloud, "_override_base", None)
    with caplog.at_level("WARNING", logger="artzain.cloud"):
        cloud._log_http_status("post", "decision", 401, b"unauthorized")
    messages = [r.getMessage() for r in caplog.records]
    assert any("HTTP 401" in m and "base URL from COGNEXUS_API_BASE_URL" in m for m in messages), messages
    assert not any("tenant-secret.example.test" in m for m in messages), messages


def test_base_url_source_is_a_label_for_every_origin(monkeypatch):
    from artzain import cloud

    monkeypatch.delenv("COGNEXUS_API_BASE_URL", raising=False)
    monkeypatch.setattr(cloud, "_override_base", "https://override.example.test")
    assert cloud._base_url_source() == "configure(base_url=...)"
    monkeypatch.setattr(cloud, "_override_base", None)
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", "https://env.example.test")
    assert cloud._base_url_source() == "COGNEXUS_API_BASE_URL"
    monkeypatch.delenv("COGNEXUS_API_BASE_URL")
    import artzain.credentials as credentials
    monkeypatch.setattr(credentials, "profile_base_url", lambda: "https://profile.example.test")
    assert cloud._base_url_source() == "credentials profile"
    monkeypatch.setattr(credentials, "profile_base_url", lambda: None)
    assert cloud._base_url_source() == "default"
