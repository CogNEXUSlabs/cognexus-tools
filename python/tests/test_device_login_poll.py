"""``artzain login`` keeps polling through a network error, and says what to do.

Survey row 57 (review). A poll that timed out (the server may be
provisioning for this code) or lost its connection raised out of the poll
loop with a traceback, and the login ended though the server went on to
issue the key. Now such a poll is tried again; a terminal answer says to run
``artzain login`` again, with the server's reason when it gave one.
"""

from __future__ import annotations

import argparse
import ssl
import time
import urllib.error

import pytest

from artzain import cli, credentials

KEY = "cnx_" + "a" * 40


@pytest.fixture
def poll(monkeypatch, tmp_path):
    import webbrowser

    monkeypatch.setattr(time, "sleep", lambda seconds: None)
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: True)
    written: list = []
    monkeypatch.setattr(credentials, "write_profile",
                        lambda **kw: written.append(kw) or (tmp_path / "credentials.toml"))
    monkeypatch.delenv("COGNEXUS_API_KEY", raising=False)

    def _answers(*answers):
        seq = iter([(200, {"device_code": "d", "user_code": "ABCD", "interval": 1,
                           "expires_in": 60}), *answers])

        def _http(*args, **kwargs):
            answer = next(seq)
            if isinstance(answer, BaseException):
                raise answer
            return answer

        monkeypatch.setattr(cli, "_http_json", _http)

    return _answers, written


def test_a_poll_that_times_out_or_loses_its_connection_is_tried_again(poll, monkeypatch):
    answers, written = poll
    answers(TimeoutError("timed out"), urllib.error.URLError("connection reset"),
            ConnectionResetError("reset"), (200, {"ok": True, "sandbox": {"api_key": {"key": KEY}}}))

    cli.cmd_login(argparse.Namespace())

    assert written and written[0]["api_key"] == KEY


@pytest.mark.parametrize("error", ["invalid_grant", "expired_token", "access_denied"])
def test_a_terminal_answer_says_to_log_in_again_with_the_reason(poll, error):
    answers, _ = poll
    answers((400, {"error": error, "error_description": "The trial has ended."}))

    with pytest.raises(SystemExit) as caught:
        cli.cmd_login(argparse.Namespace())

    message = str(caught.value)
    assert error in message and "The trial has ended." in message
    assert "artzain login" in message


@pytest.mark.parametrize("error", [
    ssl.SSLCertVerificationError(1, "certificate verify failed: Hostname mismatch, certificate is not valid for 'x.example'"),
    urllib.error.URLError(ssl.SSLCertVerificationError(1, "certificate verify failed: self-signed certificate")),
])
def test_a_certificate_that_does_not_verify_ends_the_login(poll, error):
    """It will not verify on the next poll either: polled until the code
    expired, the login said nothing for ten minutes, then "timed out". The
    message names the error's type, not its text, which can quote the
    certificate's names."""
    answers, written = poll
    answers(error, (200, {"ok": True, "sandbox": {"api_key": {"key": KEY}}}))

    with pytest.raises(SystemExit) as caught:
        cli.cmd_login(argparse.Namespace())

    message = str(caught.value)
    assert "SSLCertVerificationError" in message and "artzain login" in message
    assert "x.example" not in message and "self-signed" not in message
    assert caught.value.__context__ is None
    assert written == []
