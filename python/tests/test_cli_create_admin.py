"""`artzain local create-admin` password intake — the headless contract.

On Windows `getpass` reads the console device, not ``sys.stdin``, so with
stdin piped or absent the old code blocked forever — in CI, ssh without a
tty, and scripted installs, exactly the headless contexts the command
exists for. These tests pin the two escape hatches: an explicit
``--password-stdin``, and the automatic fallback to reading stdin when it
is not a tty. No engine is needed — ``artzain.local.run_create_admin`` is
monkeypatched at the seam the CLI calls it.
"""

from __future__ import annotations

import io
import os

import pytest

import artzain.cli as cli
import artzain.local


class _Tty(io.StringIO):
    """A stdin whose ``isatty()`` says a real console is attached."""

    def isatty(self) -> bool:
        return True


ARGS = ["local", "create-admin", "--email", "op@example.test"]


def _capture_create_admin(monkeypatch) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(artzain.local, "run_create_admin",
                        lambda email, password: calls.append((email, password)))
    return calls


def test_password_stdin_reads_the_first_line_only(monkeypatch):
    calls = _capture_create_admin(monkeypatch)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("s3cret-pw\nnot-the-password\n"))
    cli.main(ARGS + ["--password-stdin"])
    assert calls == [("op@example.test", "s3cret-pw")]


def test_password_stdin_strips_a_windows_crlf(monkeypatch):
    calls = _capture_create_admin(monkeypatch)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("windows-pw\r\n"))
    cli.main(ARGS + ["--password-stdin"])
    assert calls == [("op@example.test", "windows-pw")]


def test_password_stdin_short_password_is_the_same_exit_2(monkeypatch, capsys):
    calls = _capture_create_admin(monkeypatch)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("short\n"))
    with pytest.raises(SystemExit) as excinfo:
        cli.main(ARGS + ["--password-stdin"])
    assert excinfo.value.code == 2
    assert "Password must be at least 8 characters." in capsys.readouterr().err
    assert calls == []


def test_piped_stdin_falls_back_without_the_flag(monkeypatch, capsys):
    calls = _capture_create_admin(monkeypatch)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("piped-pw-ok\n"))
    cli.main(ARGS)
    assert calls == [("op@example.test", "piped-pw-ok")]
    # The prompt still shows (on stderr) for a human on ssh without a tty.
    assert "Choose the admin password" in capsys.readouterr().err


def test_devnull_stdin_never_reaches_getpass(monkeypatch):
    """The `< NUL` headless case. On Windows the NUL device answers
    ``isatty()`` with True — any character device does — so a naive tty
    check hands the prompt to ``getpass``, which reads the console and
    blocks forever. Only ``GetConsoleMode`` tells NUL from a console."""
    calls = _capture_create_admin(monkeypatch)

    def boom(prompt: str) -> str:
        raise AssertionError("getpass reached — this is the hang")

    monkeypatch.setattr(cli.getpass, "getpass", boom)
    with open(os.devnull, encoding="utf-8") as devnull:
        monkeypatch.setattr(cli.sys, "stdin", devnull)
        with pytest.raises(SystemExit) as excinfo:
            cli.main(ARGS)
    assert excinfo.value.code == 2
    assert calls == []


def test_absent_stdin_fails_fast_instead_of_hanging(monkeypatch):
    calls = _capture_create_admin(monkeypatch)
    monkeypatch.setattr(cli.sys, "stdin", None)
    with pytest.raises(SystemExit) as excinfo:
        cli.main(ARGS)
    assert excinfo.value.code == 2
    assert calls == []


def test_a_real_console_still_gets_the_echo_free_prompt(monkeypatch):
    calls = _capture_create_admin(monkeypatch)
    monkeypatch.setattr(cli.sys, "stdin", _Tty("typed-anyway\n"))
    prompts: list[str] = []

    def fake_getpass(prompt: str) -> str:
        prompts.append(prompt)
        return "console-pw"

    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)
    cli.main(ARGS)
    assert calls == [("op@example.test", "console-pw")]
    assert prompts == ["Choose the admin password (min 8 chars): "]
