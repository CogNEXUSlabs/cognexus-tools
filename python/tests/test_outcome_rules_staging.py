"""The SDK stages the guard's outcome rules as the platform does.

``COGNEXUS_OUTCOME_RULES`` is ``shadow`` unless set: an outcome rule
(``artzain.destructive_action_guard.OUTCOME_RULE_IDS``) that matches is
reported as what it would have decided, and decides nothing. ``enforce`` lets
it vote as every other rule of the guard does; ``off`` leaves it out.

``screen_action`` and ``DestructiveActionGuard.screen`` are not staged: they
return every match, whatever the flag. The kill switch's side of this is in
``test_kill_switch.py``.

Fixtures are named by attack pattern, with test hosts and a test recipient.
"""

from __future__ import annotations

import json

import pytest

from artzain import screen_action
from artzain.decide import _decide_offline, _offline_destructive_vote
from artzain.destructive_action_guard import (
    OUTCOME_RULE_IDS,
    ActionScreenResult,
    ActionSeverity,
    outcome_rules_mode,
    stage_outcome_rules,
)

ENCRYPT_OVERWRITE_SINGLE = (
    "gpg --batch --yes -r test-key@example.invalid -o notes.txt.gpg -e notes.txt"
    " && rm -f notes.txt && mv notes.txt.gpg notes.txt"
)
PERSIST_CRONTAB = (
    '(crontab -l 2>/dev/null; echo "*/15 * * * * /usr/bin/true # test entry") | crontab -'
)
GPG_KEY_IMPORT = "gpg --batch --yes --import release-test-key.asc"


def _call(command: str) -> str:
    return json.dumps({"tool": "run_shell", "arguments": {"command": command}})


@pytest.fixture
def mode(monkeypatch):
    def set_mode(value):
        if value is None:
            monkeypatch.delenv("COGNEXUS_OUTCOME_RULES", raising=False)
        else:
            monkeypatch.setenv("COGNEXUS_OUTCOME_RULES", value)
    return set_mode


def _vote(command: str) -> dict:
    return _offline_destructive_vote(_call(command), "tool_call", surface="sdk")


def test_the_flag_defaults_to_shadow(mode):
    mode(None)
    assert outcome_rules_mode() == "shadow"
    for value in ("off", "shadow", "enforce"):
        mode(value)
        assert outcome_rules_mode() == value
    mode(" Enforce ")
    assert outcome_rules_mode() == "enforce"
    mode("loud")
    assert outcome_rules_mode() == "shadow"


def test_screen_action_returns_every_match_whatever_the_flag(mode):
    for value in (None, "off", "shadow", "enforce"):
        mode(value)
        result = screen_action(ENCRYPT_OVERWRITE_SINGLE)
        assert [m.rule_id for m in result.matches] == ["crypto.encrypt_overwrite"], value
        assert result.severity is ActionSeverity.CRITICAL


def test_staging_splits_a_result_into_what_decides_and_what_is_staged(mode):
    mode("shadow")
    result = screen_action("rm -rf / ; " + ENCRYPT_OVERWRITE_SINGLE)
    deciding, staged = stage_outcome_rules(result)
    assert [m.rule_id for m in staged] == ["crypto.encrypt_overwrite"]
    assert not {m.rule_id for m in deciding.matches} & OUTCOME_RULE_IDS
    assert deciding.severity is ActionSeverity.CRITICAL
    assert deciding.payload_sha256 == result.payload_sha256

    mode("enforce")
    same, staged = stage_outcome_rules(result)
    assert same is result and staged == []

    mode("off")
    deciding, staged = stage_outcome_rules(result)
    assert staged == []
    assert not {m.rule_id for m in deciding.matches} & OUTCOME_RULE_IDS


def test_a_result_with_no_outcome_match_is_returned_as_it_is(mode):
    mode("shadow")
    result = screen_action("rm -rf /")
    assert stage_outcome_rules(result) == (result, [])
    assert stage_outcome_rules(result)[0] is result


def test_a_failed_screen_is_never_staged_away(mode):
    failed = ActionScreenResult(
        is_destructive=True, severity=ActionSeverity.CRITICAL, matches=[],
        explanation="guard internal error", payload_sha256="", surface="sdk")
    for value in ("off", "shadow", "enforce"):
        mode(value)
        deciding, staged = stage_outcome_rules(failed)
        assert deciding.severity is ActionSeverity.CRITICAL and deciding.is_destructive, value
        assert staged == []


def test_offline_shadow_records_and_allows(mode):
    mode(None)
    vote = _vote(ENCRYPT_OVERWRITE_SINGLE)
    assert (vote["verdict"], vote["severity"]) == ("allow", "none")
    assert len(vote["findings"]) == 1
    assert vote["findings"][0].startswith(
        "would-deny under COGNEXUS_OUTCOME_RULES=enforce: crypto.encrypt_overwrite: ")
    assert _vote(PERSIST_CRONTAB)["findings"][0].startswith("would-review under ")
    assert _vote(GPG_KEY_IMPORT)["findings"][0].startswith("would-record under ")
    decision = _decide_offline(
        action="run_shell", target="workspace:1", payload=_call(ENCRYPT_OVERWRITE_SINGLE),
        kind="tool_call", agent_did="document-builder", request_id=None)
    assert decision["outcome"] == "allow"


def test_offline_enforce_votes(mode):
    mode("enforce")
    vote = _vote(ENCRYPT_OVERWRITE_SINGLE)
    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert vote["findings"][0].startswith("crypto.encrypt_overwrite: ")
    review = _vote(PERSIST_CRONTAB)
    assert (review["verdict"], review["severity"]) == ("review", "high")
    decision = _decide_offline(
        action="run_shell", target="workspace:1", payload=_call(ENCRYPT_OVERWRITE_SINGLE),
        kind="tool_call", agent_did="document-builder", request_id=None)
    assert decision["outcome"] == "deny"


def test_offline_off_leaves_them_out(mode):
    mode("off")
    vote = _vote(ENCRYPT_OVERWRITE_SINGLE)
    assert (vote["verdict"], vote["severity"], vote["findings"]) == ("allow", "none", [])


@pytest.mark.parametrize("value", [None, "off", "shadow", "enforce"])
def test_offline_earlier_rules_decide_in_every_mode(mode, value):
    mode(value)
    vote = _offline_destructive_vote("rm -rf /", "model_output", surface="sdk")
    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert vote["findings"][0].startswith("fs.rm_rf_root: ")


def test_offline_shadow_lists_a_staged_finding_after_one_that_decides(mode):
    mode("shadow")
    vote = _offline_destructive_vote(
        "rm -rf / ; " + ENCRYPT_OVERWRITE_SINGLE, "model_output", surface="sdk")
    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert vote["findings"][0].startswith("fs.rm_rf_root: ")
    assert vote["findings"][-1].startswith(
        "would-deny under COGNEXUS_OUTCOME_RULES=enforce: crypto.encrypt_overwrite: ")
