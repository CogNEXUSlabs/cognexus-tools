"""Applying a signed trial extension from the command line (self-hosted
grant tools plan, Phase D).

CogNEXUS lengthens a self-hosted trial with a ``cognexus-trial-extension``
file, written by ``scripts/issue_trial_extension.py`` as a
``cognexus-trial-extension-bundle``. The engine checks and applies it at
``POST /api/v1/licence/trial-extension``. What this pins:

  - ``artzain licence install`` and ``artzain local activate`` read the file's
    format: an extension (bundle or bare record) goes to the extension route
    as the engine reads it, and a certificate keeps its own path untouched;
  - success prints the extension, the days added, the new end date, and says
    so when the Evidence Root was not pinned;
  - each refusal the engine names prints its message and what to do, and
    exits non-zero;
  - ``artzain local status`` shows the trial's end date, so an operator can
    see an extension took effect, and its expired hint names the extension
    file as well as a certificate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import artzain.cli as cli
from artzain import local

BASE = "http://127.0.0.1:8080"
INSTALL = "inst_" + "7f3a" * 8

RECORD = {
    "format": "cognexus-trial-extension", "format_version": 1, "install_id": INSTALL,
    "extension_id": "EXT-01TEST", "extra_days": 30, "issued_at": "2026-10-29T09:40:00+00:00",
    "apply_by": "2026-11-28T09:40:00+00:00", "reason": "pilot with Acme",
    "issuer_cert_id": "issuing-2026q4", "sig": "c2ln", "signer_key_id": "kid",
}
BUNDLE = {
    "format": "cognexus-trial-extension-bundle", "format_version": 1,
    "trial_extension": RECORD,
    "issuing_certificates": [{"format": "cognexus-issuing-certificate", "cert_id": "issuing-2026q4"}],
    "root_public_key_pem": "-----BEGIN PUBLIC KEY-----\nROOT\n-----END PUBLIC KEY-----\n",
}
APPLIED = {
    "applied": True, "extension_id": "EXT-01TEST", "extra_days": 30,
    "expires_at": "2026-12-08T10:00:00+00:00", "pinned": False, "root_fingerprint": "ab" * 8,
    "leaf_id": "01LEAF", "trial": {"applies": True, "days_remaining": 40, "extra_days": 30,
                                   "expires_at": "2026-12-08T10:00:00+00:00"},
}


def _write(tmp_path: Path, doc) -> str:
    path = tmp_path / "file.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def _args(path: str, **over) -> argparse.Namespace:
    values = dict(certificate=path, chain=None, root_key=None, issuing=None, root_fingerprint=None,
                  offline_only=False, dir=None, base_url=BASE, allow_remote=False,
                  session_token="tok")
    values.update(over)
    return argparse.Namespace(**values)


@pytest.fixture
def engine(monkeypatch):
    """The engine's answers, and every request the command sent."""
    sent = []
    state = {"answer": (200, APPLIED)}

    def fake(method, url, *, headers=None, body=None, timeout_sec=30.0):
        sent.append({"method": method, "url": url, "headers": headers or {}, "body": body})
        return state["answer"]

    monkeypatch.setattr(cli, "_http_json", fake)

    def no_offline_check(*a, **k):
        raise AssertionError("an extension is not a certificate: no certificate check")

    import artzain.licence as licence

    monkeypatch.setattr(licence, "verify_certificate_offline", no_offline_check)
    state["sent"] = sent
    return state


def test_a_bundle_goes_to_the_extension_route_as_the_engine_reads_it(tmp_path, engine, capsys):
    cli.cmd_licence_install(_args(_write(tmp_path, BUNDLE)))
    [request] = engine["sent"]
    assert request["method"] == "POST"
    assert request["url"] == f"{BASE}/api/v1/licence/trial-extension"
    assert request["body"] == {"trial_extension": RECORD,
                               "issuing_certificates": BUNDLE["issuing_certificates"],
                               "root_public_key_pem": BUNDLE["root_public_key_pem"]}
    assert request["headers"] == {"Authorization": "Bearer tok"}
    out = capsys.readouterr().out
    assert "Trial extension EXT-01TEST applied: +30 days." in out
    assert "Trial now ends: 2026-12-08 (40 days left)." in out


def test_an_unpinned_root_is_said_plainly(tmp_path, engine, capsys):
    cli.cmd_licence_install(_args(_write(tmp_path, BUNDLE)))
    out = capsys.readouterr().out
    assert "not pinned" in out
    engine["sent"].clear()
    engine["answer"] = (200, {**APPLIED, "pinned": True})
    cli.cmd_licence_install(_args(_write(tmp_path, BUNDLE)))
    assert "not pinned" not in capsys.readouterr().out


def test_a_bare_record_is_sent_wrapped(tmp_path, engine):
    cli.cmd_licence_install(_args(_write(tmp_path, RECORD)))
    [request] = engine["sent"]
    assert request["body"] == {"trial_extension": RECORD}


def test_the_chain_flags_fill_in_what_the_file_leaves_out(tmp_path, engine):
    root = tmp_path / "root.pem"
    root.write_text("-----BEGIN PUBLIC KEY-----\nOTHER\n-----END PUBLIC KEY-----\n", encoding="utf-8")
    cli.cmd_licence_install(_args(_write(tmp_path, RECORD), root_key=str(root)))
    [request] = engine["sent"]
    assert request["body"]["root_public_key_pem"].endswith("OTHER\n-----END PUBLIC KEY-----\n")


def test_offline_only_has_nothing_to_write_for_an_extension(tmp_path, engine, capsys):
    with pytest.raises(SystemExit) as stop:
        cli.cmd_licence_install(_args(_write(tmp_path, BUNDLE), offline_only=True))
    assert stop.value.code == 2
    assert engine["sent"] == []
    assert "applied by the deployment" in capsys.readouterr().err


@pytest.mark.parametrize("code, hint", [
    ("already_applied", "already in effect"),
    ("wrong_install", "different install"),
    ("apply_by_passed", "new one"),
    ("install_certified", "no longer on trial"),
    ("cap_exceeded", "180 days"),
    ("bad_signature", "altered"),
    ("root_not_pinned", "new file"),
])
def test_each_named_refusal_prints_its_message_and_what_to_do(tmp_path, engine, capsys, code, hint):
    message = f"Trial extension refused: because {code}."
    engine["answer"] = (409, {"detail": {"error": code, "message": message}})
    with pytest.raises(SystemExit) as stop:
        cli.cmd_licence_install(_args(_write(tmp_path, BUNDLE)))
    assert stop.value.code == 1
    err = capsys.readouterr().err
    assert message in err
    assert hint in err
    assert "{" not in err, "the refusal is said, not dumped as a dict"


def test_an_unnamed_refusal_still_says_what_the_engine_said(tmp_path, engine, capsys):
    engine["answer"] = (503, {"detail": "could not seal the extension; nothing was applied"})
    with pytest.raises(SystemExit):
        cli.cmd_licence_install(_args(_write(tmp_path, BUNDLE)))
    assert "nothing was applied" in capsys.readouterr().err


def test_a_certificate_bundle_keeps_its_own_path(tmp_path, monkeypatch, capsys):
    import artzain.licence as licence

    sent = []
    monkeypatch.setattr(cli, "_http_json", lambda method, url, **kw: (
        sent.append(url) or (200, {"cert_id": "DEP-1"})))
    monkeypatch.setattr(licence, "verify_certificate_offline", lambda *a, **k: (True, "ok", True))
    cert = {"format": "cognexus-licence-certificate", "cert_id": "DEP-1", "install_id": INSTALL}
    bundle = {"format": "cognexus-licence-certificate-bundle", "certificate": cert,
              "issuing_certificates": [], "root_public_key_pem": "pem"}
    cli.cmd_licence_install(_args(_write(tmp_path, bundle)))
    assert sent == [f"{BASE}/api/v1/licence/certificate"]


def test_local_activate_applies_an_extension_to_the_local_engine(tmp_path, engine, monkeypatch):
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnx_test_key")
    monkeypatch.setattr(cli, "resolve_api_key_for_quickstart", lambda *a, **k: ("cnx_test_key", None))
    monkeypatch.setattr(local, "request_base_url", lambda: BASE)
    ns = argparse.Namespace(certificate=_write(tmp_path, BUNDLE), chain=None, root_key=None,
                            issuing=None, root_fingerprint=None)
    cli.cmd_local_activate(ns)
    [request] = engine["sent"]
    assert request["url"] == f"{BASE}/api/v1/licence/trial-extension"


# ---------------------------------------------------------------------------
# artzain local status
# ---------------------------------------------------------------------------


def _status(monkeypatch, trial) -> str:
    import io

    monkeypatch.setattr(local, "applied_pins", lambda: None)
    monkeypatch.setattr(local, "fetch_health", lambda: {"status": "ok", "profile": "core", "trial": trial})
    out = io.StringIO()
    local.run_status(None, out=out)
    return out.getvalue()


def test_status_shows_when_the_trial_ends(monkeypatch):
    text = _status(monkeypatch, {"applies": True, "expired": False, "days_remaining": 40,
                                 "expires_at": "2026-12-08T10:00:00+00:00"})
    assert "Trial     : 40 day(s) remaining, ends 2026-12-08" in text


def test_status_without_an_end_date_still_counts_days(monkeypatch):
    text = _status(monkeypatch, {"applies": True, "expired": False, "days_remaining": 3})
    assert "Trial     : 3 day(s) remaining" in text and "ends" not in text


def test_the_expired_hint_names_the_extension_file_too(monkeypatch):
    text = _status(monkeypatch, {"applies": True, "expired": True, "days_remaining": 0,
                                 "expires_at": "2026-10-01T10:00:00+00:00"})
    assert "artzain local activate" in text
    assert "trial extension" in text
    assert "ended 2026-10-01" in text
