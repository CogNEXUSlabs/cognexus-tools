"""``artzain gui`` API-key bootstrap: token pass-through and MFA challenge."""

from __future__ import annotations

import io
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

_PKG = Path(__file__).resolve().parents[1] / "src"
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from artzain import gui  # noqa: E402


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _patch_upstream(monkeypatch, payload: dict):
    seen: dict = {}

    def _urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["api_key"] = req.get_header("X-api-key")
        return _Resp(json.dumps(payload).encode())

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    return seen


def test_bootstrap_returns_session_payload(monkeypatch):
    seen = _patch_upstream(
        monkeypatch, {"token": "jwt", "email": "k@example.test", "display_name": "K"}
    )
    out = gui._try_bootstrap("https://api.example.test/", "cnx_live_valid")
    assert seen["url"] == "https://api.example.test/api/auth/token"
    assert seen["api_key"] == "cnx_live_valid"
    assert out["token"] == "jwt"
    assert out["email"] == "k@example.test"


def test_bootstrap_surfaces_mfa_challenge(monkeypatch):
    """A TOTP-protected account gets a challenge, never a token, from
    ``/api/auth/token``; the GUI must say so rather than pretend no key exists."""
    _patch_upstream(monkeypatch, {"mfa_required": True, "mfa_token": "pending"})
    out = gui._try_bootstrap("https://api.example.test", "cnx_live_valid")
    assert out is not None
    assert out["token"] is None
    assert out["mfa_required"] is True
    assert "pending" not in json.dumps(out)
    assert "two-factor" in out["error"].lower() or "authenticator" in out["error"].lower()


def test_bootstrap_returns_none_on_rejected_key(monkeypatch):
    def _urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    assert gui._try_bootstrap("https://api.example.test", "bad") is None
