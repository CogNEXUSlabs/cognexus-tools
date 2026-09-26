"""An API key goes only to the host it was issued with.

``artzain login`` writes the key and the host it logged in against to the
credentials profile, and ``artzain quickstart`` writes both to a project
``.env``. The CLI read only the key from either and took the host from
``COGNEXUS_API_BASE_URL`` or the production default, so a self-hosted
deployment's key went to the public host. The library and the TypeScript SDK
resolved the key and the host independently, so a key could be paired with
the profile's host, or the profile's key with another host.

The rule these tests pin: a key read from the profile (or a runtime key equal
to it) goes to the profile's host; a key read from a ``.env`` goes to that
file's host; any other key goes to ``configure(base_url=...)``,
``COGNEXUS_API_BASE_URL`` or the default. When a set host disagrees with the
host the key belongs to, nothing is sent and the error names the settings,
never their values.
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging

import pytest

SELF_HOSTED = "https://engine.selfhosted.example"
OTHER = "https://other.example"
DEFAULT = "https://app.cognexuslabs.ai"
PROFILE_KEY = "cnx_profile_key_0123456789"


@pytest.fixture
def clean(tmp_path, monkeypatch):
    """No key or host from the machine running the tests."""
    from artzain import cli, cloud

    for name in ("COGNEXUS_API_KEY", "MYAPP_API_KEY", "COGNEXUS_API_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp_path / "credentials.toml"))
    monkeypatch.setattr(cloud, "_override_key", None)
    monkeypatch.setattr(cloud, "_override_base", None)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)

    def _only_work_dir(start=None):
        for name in cli._ENV_FILENAMES:
            candidate = work / name
            if candidate.is_file():
                yield candidate

    monkeypatch.setattr(cli, "_iter_dotenv_paths", _only_work_dir)
    return work


def _profile(base_url: str = SELF_HOSTED, key: str = PROFILE_KEY) -> None:
    from artzain import credentials

    credentials.write_profile(api_key=key, base_url=base_url)


def _capture_cli(monkeypatch) -> list[tuple[str, str, dict]]:
    from artzain import cli

    calls: list[tuple[str, str, dict]] = []

    def _fake_http_json(method, url, *, headers=None, body=None, timeout_sec=30.0):
        calls.append((method, url, dict(headers or {})))
        return 200, {"entries": [], "total": 0}

    monkeypatch.setattr(cli, "_http_json", _fake_http_json)
    return calls


def _registry_list() -> None:
    from artzain import cli

    cli.cmd_registry_list(argparse.Namespace(limit=10, q=None, source=None, lifecycle=None, json=True))


class _Resp:
    status = 200

    def __init__(self, body: dict):
        self._body = json.dumps(body).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _capture_decide(monkeypatch) -> list[tuple[str, str]]:
    # The package re-exports the decide() function under the module's name.
    decide_mod = importlib.import_module("artzain.decide")

    calls: list[tuple[str, str]] = []

    def _urlopen(req, timeout=None):
        calls.append((req.full_url, req.get_header("X-api-key")))
        return _Resp({"outcome": "allow", "decision_id": "d", "audit_block_id": "b",
                      "contributing_agents": [], "reasons": []})

    monkeypatch.setattr(decide_mod.urllib.request, "urlopen", _urlopen)
    return calls


def _decide():
    from artzain.decide import decide

    return decide(action="send_email", target="crm:contact:1", payload="hello", kind="user_input")


# --- CLI ---------------------------------------------------------------------


def test_cli_sends_the_profile_key_to_the_profile_host(clean, monkeypatch):
    _profile()
    calls = _capture_cli(monkeypatch)
    _registry_list()
    assert len(calls) == 1
    _method, url, headers = calls[0]
    assert url.startswith(SELF_HOSTED + "/api/v1/registry/catalog"), url
    assert headers.get("X-Api-Key") == PROFILE_KEY


def test_cli_sends_a_dotenv_key_to_that_files_host(clean, monkeypatch):
    (clean / ".env").write_text(
        f"COGNEXUS_API_BASE_URL={SELF_HOSTED}\nCOGNEXUS_API_KEY=cnx_dotenv_key_0123456789\n",
        encoding="utf-8",
    )
    calls = _capture_cli(monkeypatch)
    _registry_list()
    assert calls[0][1].startswith(SELF_HOSTED + "/"), calls[0][1]
    assert calls[0][2].get("X-Api-Key") == "cnx_dotenv_key_0123456789"


def test_cli_refuses_a_profile_key_for_another_named_host(clean, monkeypatch):
    _profile()
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", OTHER)
    calls = _capture_cli(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        _registry_list()
    assert calls == []
    message = str(exc.value)
    assert "COGNEXUS_API_BASE_URL" in message and "credentials profile" in message
    assert SELF_HOSTED not in message and PROFILE_KEY not in message


def test_cli_refuses_a_dotenv_key_for_another_named_host(clean, monkeypatch):
    (clean / ".env").write_text(
        f"COGNEXUS_API_KEY=cnx_dotenv_key_0123456789\nCOGNEXUS_API_BASE_URL={SELF_HOSTED}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", OTHER)
    calls = _capture_cli(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        _registry_list()
    assert calls == []
    assert "cnx_dotenv_key_0123456789" not in str(exc.value)


def test_cli_env_key_without_a_host_goes_to_the_default(clean, monkeypatch):
    _profile()
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnx_env_key_0123456789")
    calls = _capture_cli(monkeypatch)
    _registry_list()
    assert calls[0][1].startswith(DEFAULT + "/"), calls[0][1]


# --- library -----------------------------------------------------------------


def test_decide_refuses_a_profile_key_for_another_named_host(clean, monkeypatch):
    from artzain.decide import DecisionError

    _profile()
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", OTHER)
    calls = _capture_decide(monkeypatch)
    with pytest.raises(DecisionError) as exc:
        _decide()
    assert calls == []
    message = str(exc.value)
    assert "COGNEXUS_API_BASE_URL" in message and "credentials profile" in message
    assert SELF_HOSTED not in message and OTHER not in message and PROFILE_KEY not in message


def test_decide_refuses_a_profile_key_for_a_configured_host(clean, monkeypatch):
    from artzain import cloud
    from artzain.decide import DecisionError

    _profile()
    monkeypatch.setattr(cloud, "_override_base", OTHER)
    calls = _capture_decide(monkeypatch)
    with pytest.raises(DecisionError):
        _decide()
    assert calls == []


def test_decide_sends_an_env_key_to_the_default_not_the_profile_host(clean, monkeypatch):
    _profile()
    monkeypatch.setenv("COGNEXUS_API_KEY", "cnx_env_key_0123456789")
    calls = _capture_decide(monkeypatch)
    _decide()
    assert calls == [(DEFAULT + "/api/v1/decisions", "cnx_env_key_0123456789")]


def test_decide_sends_the_profile_key_exported_to_env_to_the_profile_host(clean, monkeypatch):
    _profile()
    monkeypatch.setenv("COGNEXUS_API_KEY", PROFILE_KEY)
    calls = _capture_decide(monkeypatch)
    _decide()
    assert calls == [(SELF_HOSTED + "/api/v1/decisions", PROFILE_KEY)]


def test_decide_pairs_a_configured_key_with_the_configured_host(clean, monkeypatch):
    from artzain import cloud

    _profile()
    monkeypatch.setattr(cloud, "_override_key", "cnx_configured_key_0123")
    monkeypatch.setattr(cloud, "_override_base", OTHER)
    calls = _capture_decide(monkeypatch)
    _decide()
    assert calls == [(OTHER + "/api/v1/decisions", "cnx_configured_key_0123")]


def test_a_profile_without_a_host_keeps_the_named_host(clean, monkeypatch):
    """Profiles written without ``base_url`` say nothing about the key's host."""
    from artzain import credentials

    credentials.credentials_path().write_text(
        f'[default]\napi_key = "{PROFILE_KEY}"\n', encoding="utf-8")
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", OTHER)
    calls = _capture_decide(monkeypatch)
    _decide()
    assert calls == [(OTHER + "/api/v1/decisions", PROFILE_KEY)]


def test_events_are_skipped_on_a_conflict_and_the_warning_names_settings(clean, monkeypatch, caplog):
    from artzain import cloud

    _profile()
    monkeypatch.setenv("COGNEXUS_API_BASE_URL", OTHER)
    queued: list = []
    monkeypatch.setattr(cloud, "_enqueue_post", lambda item: queued.append(item) or True)
    monkeypatch.setattr(cloud, "_session_logged", True)
    with caplog.at_level(logging.WARNING, logger="artzain"):
        cloud.post_sdk_event("guard.block", title="t", payload={})
    assert queued == []
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "COGNEXUS_API_BASE_URL" in text and "credentials profile" in text
    assert SELF_HOSTED not in text and OTHER not in text and PROFILE_KEY not in text
