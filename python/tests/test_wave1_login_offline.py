"""Tests for offline-fallback prompt (R2) and credentials profile (R1)."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

# Ensure package importable from repo checkout
_PKG = Path(__file__).resolve().parents[1] / "src"
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))


def test_offline_warns_once(monkeypatch, capsys):
    import importlib
    decide_mod = importlib.import_module("artzain.decide")

    decide_mod._reset_offline_warn_for_tests()
    monkeypatch.delenv("COGNEXUS_API_KEY", raising=False)
    monkeypatch.delenv("MYAPP_API_KEY", raising=False)
    monkeypatch.delenv("COGNEXUS_QUIET", raising=False)
    monkeypatch.setattr(decide_mod, "_effective_key", lambda: None)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)

    r1 = decide_mod.decide(action="noop", target="t", payload="hello", kind="user_input")
    r2 = decide_mod.decide(action="noop", target="t", payload="hello", kind="user_input")
    assert r1.get("offline") is True
    assert r2.get("offline") is True
    err = capsys.readouterr().err
    assert err.count("artzain login") == 1


def test_offline_quiet_suppresses(monkeypatch, capsys):
    import importlib
    decide_mod = importlib.import_module("artzain.decide")

    decide_mod._reset_offline_warn_for_tests()
    monkeypatch.setenv("COGNEXUS_QUIET", "1")
    monkeypatch.setattr(decide_mod, "_effective_key", lambda: None)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    decide_mod.decide(action="noop", target="t", payload="hello", kind="user_input")
    assert "artzain login" not in capsys.readouterr().err


def test_profile_write_and_env_beats_profile(tmp_path, monkeypatch):
    from artzain import cloud, credentials

    path = tmp_path / "credentials.toml"
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(path))
    monkeypatch.delenv("COGNEXUS_API_KEY", raising=False)
    monkeypatch.delenv("MYAPP_API_KEY", raising=False)
    cloud.configure(api_key=None)

    credentials.write_profile(api_key="from_profile", base_url="https://example.test")
    assert credentials.profile_api_key() == "from_profile"
    assert cloud._effective_key() == "from_profile"

    monkeypatch.setenv("COGNEXUS_API_KEY", "from_env")
    assert cloud._effective_key() == "from_env"

    if sys.platform != "win32":
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600
