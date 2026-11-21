"""``artzain redteam run``: the replay's report at the command line.

The command asks the engine for a dry-run replay of its attack-pattern
fixtures against the team's policy and prints each step. These tests stand in
for the engine with a canned report; nothing is sent anywhere.
"""

from __future__ import annotations

import contextlib
import io
import json
from types import SimpleNamespace

import pytest

from artzain import cli

NOTICE = ("Self-attested. This is a replay of attack-pattern fixtures written by CogNEXUS Labs "
          "against this team's policy on this deployment. It is not a benchmark score, and it "
          "says nothing about an attack outside the set.")

REPORT = {
    "format": "artzain-redteam-replay-v1",
    "notice": NOTICE,
    "fixtures": {"version": "1.0.0", "scenarios": 2, "steps": 3},
    "policy": {"bundle": "containment:1.0.0", "bundle_id": "b-recipe"},
    "agent_did": "redteam-replay",
    "settings": {"outcome_rules": "shadow", "session_taint": "shadow"},
    "summary": {"attack_steps": 2, "held": 1, "held_if_enforced": 2, "control_steps": 1,
                "controls_allowed": 1, "controls_allowed_if_enforced": 1},
    "scenarios": [
        {"id": "fetch_package_curl", "title": "A document asks for a package to be downloaded",
         "control": False, "steps": [
             {"id": "fetch", "kind": "tool_call", "action": "run_shell", "expect": "held",
              "outcome": "review", "outcome_if_enforced": "review",
              "decided_by": ["policy-enforcement"], "would": []},
             {"id": "run", "kind": "tool_call", "action": "run_shell", "expect": "held",
              "outcome": "allow", "outcome_if_enforced": "deny", "decided_by": [],
              "would": ["destructive-action: would-deny under COGNEXUS_OUTCOME_RULES=enforce: x"]},
         ]},
        {"id": "control_plain_shell", "title": "Control: an ordinary command", "control": True,
         "steps": [
             {"id": "run", "kind": "tool_call", "action": "run_shell", "expect": "allowed",
              "outcome": "allow", "outcome_if_enforced": "allow", "decided_by": [], "would": []},
         ]},
    ],
}


@pytest.fixture
def engine(monkeypatch):
    calls = []
    answer = {"status": 200, "body": REPORT}

    def http_json(method, url, *, headers=None, body=None, timeout_sec=30.0):
        calls.append({"method": method, "url": url, "body": body, "timeout": timeout_sec})
        return answer["status"], answer["body"]

    monkeypatch.setattr(cli, "_http_json", http_json)
    monkeypatch.setattr(cli, "_cli_credentials",
                        lambda: SimpleNamespace(base_url="https://engine.example"))
    monkeypatch.setattr(cli, "_policy_auth_headers", lambda creds=None: {})
    return SimpleNamespace(calls=calls, answer=answer)


def _run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), pytest.raises(SystemExit) as exit_info:
        cli.main(["redteam", "run", *argv])
    return exit_info.value.code, out.getvalue()


def test_it_posts_to_the_replay_route_and_prints_each_step(engine):
    code, text = _run()
    assert code == 0
    [call] = engine.calls
    assert (call["method"], call["url"]) == ("POST", "https://engine.example/api/v1/redteam/replay")
    assert call["body"] == {}
    assert call["timeout"] == 120.0
    lines = text.splitlines()
    assert lines[0] == NOTICE
    assert "Policy: containment:1.0.0   Agent: redteam-replay   Fixtures: v1.0.0, 2 scenarios, " \
           "3 steps" in text
    assert "Settings: outcome_rules=shadow, session_taint=shadow" in text
    assert "fetch_package_curl: A document asks for a package to be downloaded" in text
    assert any(line.split() == ["fetch", "tool_call", "expect", "held", "review", "by",
                                "policy-enforcement"] for line in lines), text
    assert any("allow (if enforced: deny)" in line for line in lines)
    assert "Attack steps held: 1 of 2 now, 2 if every staged control were enforced." in text
    assert "Control steps allowed: 1 of 1 now, 1 if enforced." in text


def test_the_bundle_and_the_agent_are_sent_when_given(engine):
    _run("--bundle", "b-draft", "--agent", "document-builder")
    assert engine.calls[0]["body"] == {"bundle_id": "b-draft", "agent_did": "document-builder"}


def test_json_prints_the_report_as_it_came(engine):
    code, text = _run("--json")
    assert code == 0
    assert json.loads(text) == REPORT


def test_a_refusal_is_reported_with_the_engines_reason(engine):
    engine.answer.update(status=403, body={"detail": "Requires team role in ['owner', 'admin'] "
                                                     "(caller role: member)."})
    code, text = _run()
    assert "replay failed (403)" in str(code)
    assert "owner" in str(code)
    assert text == ""


def test_the_help_says_it_is_a_dry_run_and_self_attested(capsys):
    with pytest.raises(SystemExit):
        cli.main(["redteam", "run", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    assert "nothing is sealed, billed or counted" in text
    assert "self-attested" in text
    assert "not a benchmark score" in text
