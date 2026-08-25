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


def test_flush_cloud_events_waits_for_background_post(monkeypatch):
    configure(api_key="unit-key", base_url="https://example.com")
    done = threading.Event()

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def read(self):
            return b"{}"

    def _slow_urlopen(req, timeout=None):
        time.sleep(0.05)
        done.set()
        return _Resp()

    monkeypatch.setattr(cloud.urllib.request, "urlopen", _slow_urlopen)
    post_sdk_event("flush_test", payload={"n": 1})
    assert not done.is_set()
    flush_cloud_events(timeout_sec=2.0)
    assert done.is_set()


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
