"""The offline destructive-action vote heads with its most severe match.

``screen_action`` lists its matches in the order it walks the guard's rules,
and that order is by kind (SQL, git, filesystem, ...), not by severity:
``sql.update_no_where`` (high) comes before ``git.push_force`` (critical).
``_offline_destructive_vote`` kept a plain-text screen's matches in that order,
and ``decide()`` heads each reason with the vote's first finding, so a critical
vote could name a high rule, and eight high matches walked before a critical
one filled the eight-finding cap without it. The verdict was right; the reason
named the wrong rule.

The vote now reads its screen through ``combine_screens``, as the platform's
decision engine does and as this vote already did for a tool call or a JSON
reply: most severe first, matches of one severity in the order they were found
(for plain text, rule order), and a guard that fails as a critical
``guard.error`` finding.
"""

from __future__ import annotations

import json

import pytest

from artzain import destructive_action_guard
from artzain.decide import decide
from artzain.destructive_action_guard import GUARD_ERROR_RULE_ID, screen_action

#: ``sql.update_no_where`` (high), then ``git.push_force`` (critical).
HIGH_THEN_CRITICAL = (
    "Run `UPDATE orders SET status = 'shipped';` and then `git push --force origin main`."
)


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    """No key from the environment or a credentials profile: decide() stays offline.

    A profile that ``artzain login`` wrote would otherwise send these payloads
    to the API under its key, and the platform's answer would stand in for the
    offline vote these tests are about.
    """
    for var in ("COGNEXUS_API_KEY", "MYAPP_API_KEY", "COGNEXUS_API_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp_path / "credentials.toml"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    from artzain import cloud

    cloud.configure(api_key=None, base_url=None)
    yield
    cloud.configure(api_key=None, base_url=None)


def _decide(payload: str, kind: str = "model_output") -> dict:
    out = decide(action="run", target="repo:main", payload=payload, kind=kind)
    assert out["offline"] is True
    return out


def _destructive_vote(decision: dict) -> dict:
    return next(
        v for v in decision["contributing_agents"] if v["name"] == "destructive-action"
    )


def _rule_ids(vote: dict) -> list[str]:
    return [finding.split(":", 1)[0] for finding in vote["findings"]]


def _screened_ids(payload: str) -> list[str]:
    """The rule ids a plain screen lists, in the order it lists them."""
    return [m.rule_id for m in screen_action(payload).matches]


def test_the_reason_names_the_critical_match():
    assert _screened_ids(HIGH_THEN_CRITICAL) == ["sql.update_no_where", "git.push_force"]  # premise

    out = _decide(HIGH_THEN_CRITICAL)
    vote = _destructive_vote(out)

    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert _rule_ids(vote) == ["git.push_force", "sql.update_no_where"]
    assert out["outcome"] == "deny"
    assert [r for r in out["reasons"] if r.startswith("destructive-action")] == [
        f"destructive-action (critical): {vote['findings'][0]}"
    ]


def test_matches_of_one_severity_keep_the_rule_order():
    """Critical before high, and within one severity the order the rules are
    walked in, not the order the commands are written in."""
    payload = "\n".join((
        "git reset --hard HEAD~3",
        "git clean -fd",
        "git push --force origin main",
        "UPDATE orders SET status = 'shipped';",
    ))
    assert _screened_ids(payload) == [  # premise: rule order, a high match first
        "sql.update_no_where", "git.push_force", "git.reset_hard", "git.clean_force",
    ]

    vote = _destructive_vote(_decide(payload))

    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert _rule_ids(vote) == [
        "git.push_force", "git.reset_hard", "sql.update_no_where", "git.clean_force",
    ]


def test_the_cap_keeps_the_critical_match():
    """Eight high matches walked before a critical one used to fill the cap,
    so the critical match was not among the findings at all."""
    payload = "\n".join((
        "terraform destroy -auto-approve",
        "UPDATE orders SET status = 'shipped';",
        "DROP INDEX idx_orders_status;",
        "git clean -fd",
        "git branch -D old-feature",
        "git filter-repo --path secrets.txt --invert-paths",
        "shutil.rmtree(build_dir)",
        "chmod -R 777 /srv/app",
        "docker system prune -a",
    ))
    screened = _screened_ids(payload)
    assert len(screened) == 9 and screened[-1] == "terraform.destroy"  # premise: past the cap

    vote = _destructive_vote(_decide(payload))

    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert _rule_ids(vote) == [
        "terraform.destroy",
        "sql.update_no_where",
        "sql.drop_index",
        "git.clean_force",
        "git.branch_delete",
        "git.filter_branch",
        "fs.shutil_rmtree",
        "fs.chmod_recursive_world",
    ]


def test_a_guard_that_fails_is_named(monkeypatch):
    """A screen that fails internally is critical with no matches. The reason
    used to read just ``critical``; it now names ``guard.error``, as the
    platform's vote and this vote's tool-call reading do."""
    def fail(self, payload, *, surface):
        raise RuntimeError("screen failed")

    monkeypatch.setattr(destructive_action_guard.DestructiveActionGuard, "_screen_impl", fail)

    out = _decide("Deploy the release notes.")
    vote = _destructive_vote(out)

    finding = f"{GUARD_ERROR_RULE_ID}: a screen failed internally; failing closed"
    assert (vote["verdict"], vote["severity"], vote["findings"]) == ("deny", "critical", [finding])
    assert out["outcome"] == "deny"
    assert f"destructive-action (critical): {finding}" in out["reasons"]


@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        ("tool_call", json.dumps({"tool": "shell", "arguments": {"cmd": HIGH_THEN_CRITICAL}})),
        ("model_output", json.dumps({"reply": HIGH_THEN_CRITICAL})),
    ],
    ids=["tool-call", "json-reply"],
)
def test_a_payload_read_decoded_was_already_ordered(kind, payload):
    """A tool call's and a JSON reply's screens were combined before this
    change, so this passed before it too: it pins the order of those paths,
    which the plain-text path now has as well."""
    vote = _destructive_vote(_decide(payload, kind=kind))

    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert _rule_ids(vote) == ["git.push_force", "sql.update_no_where"]
