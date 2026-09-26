"""``artzain gui`` API-key bootstrap: token pass-through, MFA challenge and a
refused key."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

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


_AGENT_KEY_DETAIL = (
    "An API key bound to an agent cannot open a session. Use a key that "
    "is not bound to an agent, or sign in with your password."
)


def _refuse(monkeypatch, body: bytes, code: int = 403) -> list:
    calls: list = []

    def _urlopen(req, timeout=None):
        calls.append(req.full_url)
        raise urllib.error.HTTPError(
            req.full_url, code, "Forbidden",
            {"Content-Type": "application/json"}, io.BytesIO(body),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)
    return calls


def test_bootstrap_surfaces_refused_key_reason(monkeypatch):
    """A key the platform will not open a session for (403) is not a missing
    key: the GUI passes the platform's reason on instead of dropping it."""
    _refuse(monkeypatch, json.dumps({"detail": _AGENT_KEY_DETAIL}).encode())
    out = gui._try_bootstrap("https://api.example.test", "cnx_live_agent")
    assert out == {"token": None, "key_refused": True, "error": _AGENT_KEY_DETAIL}


def test_bootstrap_refusal_without_a_reason_still_points_to_sign_in(monkeypatch):
    for body in (b"", b"<html>Forbidden</html>", b'{"detail": [{"msg": "x"}]}',
                 b'["detail"]', b'{"detail": "   "}', b"\xff\xfe"):
        _refuse(monkeypatch, body)
        out = gui._try_bootstrap("https://api.example.test", "cnx_live_agent")
        assert out is not None, body
        assert out["token"] is None and out["key_refused"] is True, body
        assert "not bound to an agent" in out["error"], body
        assert "sign in with your password" in out["error"], body


def test_bootstrap_refusal_reason_is_bounded(monkeypatch):
    for size in (5_000, 1_000_000):
        _refuse(monkeypatch, json.dumps({"detail": "x" * size}).encode())
        out = gui._try_bootstrap("https://api.example.test", "cnx_live_agent")
        assert out["key_refused"] is True
        assert 0 < len(out["error"]) <= 500
    # A long reason is shortened, not replaced.
    _refuse(monkeypatch, json.dumps({"detail": "x" * 5_000}).encode())
    assert set(gui._try_bootstrap("https://api.example.test", "k")["error"]) == {"x"}


def _bootstrap_handler(api_key: str = "cnx_live_agent"):
    handler_cls = gui._make_handler("https://api.example.test", b"", api_key)
    h = handler_cls.__new__(handler_cls)
    served: list = []
    h._serve_json = lambda status, data: served.append((status, data))
    return h, served


def test_gui_bootstrap_serves_refusal_uncached(monkeypatch):
    """``/gui/bootstrap`` hands the refusal to the page and asks again on the
    next load, so unbinding the key on the dashboard takes effect on reload."""
    calls = _refuse(monkeypatch, json.dumps({"detail": _AGENT_KEY_DETAIL}).encode())
    h, served = _bootstrap_handler()
    h._handle_gui_bootstrap()
    h._handle_gui_bootstrap()
    assert len(calls) == 2
    assert served == [
        (200, {"token": None, "key_refused": True, "error": _AGENT_KEY_DETAIL}),
    ] * 2


# ── The served page ──────────────────────────────────────────────────────────
#
# boot() is lifted out of the page and run under node with the page's helpers
# stubbed, so the splash and login-form text are checked as the browser would
# set them.

_BOOT_HARNESS = r"""
const vm = require('vm');
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const shown = [];
const ctx = {
  bootSub: { textContent: '' },
  loginError: { textContent: '' },
  fetch: async (url) => url === '/gui/bootstrap'
    ? { ok: true, json: async () => input.bootstrap }
    : { ok: false, json: async () => ({}) },
  setToken() {}, setEmail() {}, clearAuth() {},
  getToken: () => null, getEmail: () => '', authHeaders: () => ({}),
  showChat() { shown.push('chat'); },
  ensureConversation: async () => {},
  showLogin() { shown.push('login'); ctx.loginError.textContent = ''; },
  setTimeout: (fn) => fn(),
};
vm.createContext(ctx);
vm.runInContext(input.boot, ctx);
ctx.boot().then(() => process.stdout.write(JSON.stringify({
  bootSub: ctx.bootSub.textContent, loginError: ctx.loginError.textContent, shown,
})));
"""


def _page_boot_source() -> str:
    page = gui._GUI_HTML_TEMPLATE
    start = page.index("  async function boot() {")
    end = page.index("\n  }\n", start) + len("\n  }\n")
    return page[start:end]


def _run_boot(tmp_path, bootstrap: dict) -> dict:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("CI"):
            pytest.fail("node is required to check the served page's boot()")
        pytest.skip("node not installed")
    harness = tmp_path / "boot_harness.js"
    harness.write_text(_BOOT_HARNESS, encoding="utf-8")
    proc = subprocess.run(
        [node, str(harness)],
        input=json.dumps({"boot": _page_boot_source(), "bootstrap": bootstrap}),
        capture_output=True, text=True, encoding="utf-8", timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_page_shows_refused_key_reason(tmp_path):
    out = _run_boot(tmp_path, {"token": None, "key_refused": True, "error": _AGENT_KEY_DETAIL})
    assert out["shown"] == ["login"]
    assert "No API key found" not in out["bootSub"]
    assert "sign in" in out["bootSub"]
    assert out["loginError"] == _AGENT_KEY_DETAIL


def test_page_mfa_notice_unchanged(tmp_path):
    out = _run_boot(tmp_path, {"token": None, "mfa_required": True, "error": gui._MFA_BOOTSTRAP_ERROR})
    assert out["shown"] == ["login"]
    assert out["bootSub"].startswith("Two-factor authentication required")
    assert out["loginError"] == gui._MFA_BOOTSTRAP_ERROR


def test_page_without_a_key_says_so(tmp_path):
    out = _run_boot(tmp_path, {"token": None, "error": "No API key configured."})
    assert out["shown"] == ["login"]
    assert out["bootSub"].startswith("No API key found")
    assert out["loginError"] == ""
