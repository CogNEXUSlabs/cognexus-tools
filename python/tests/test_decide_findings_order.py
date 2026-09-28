"""The offline policy vote seals its most severe findings, not its first ones.

``_offline_policy_vote`` seals at most eight findings, and
``PolicyEnforcementEvaluator.evaluate`` appends the conduct findings after every
rule finding. Eight matching rules therefore pushed the critical
``CONDUCT-PROFANITY-CLIENT`` finding off the end, and ``decide()`` heads each
reason with ``findings[0]``: the vote's severity read ``critical`` while the
reason named a low rule. The verdict was right, the audit trail named the wrong
rule. The platform had the same gap in
``services.decision_engine.BundleRulesEnforcer.evaluate``.

The built-in conduct rules carry no patterns of their own, so it takes rules of
the user's to reach the cap. Offline, the vote screens the rules
``load_client_policy_rules()`` returns: the configured rules followed by the
built-in conduct rules, as ``artzain._helpers._with_conduct_rules`` builds the
list the platform screens for a tenant. These tests configure their rules the
way a user does, through ``COGNEXUS_POLICY_RULES_JSON``.
"""

from __future__ import annotations

import json

import pytest

from artzain import _helpers
from artzain.decide import decide
from artzain.policy_enforcement import (
    UNPAIRED_SURROGATE_RULE_ID,
    ClientPolicyRule,
)

#: Profanity in a customer context: CONDUCT-PROFANITY-CLIENT, critical.
PROFANITY_AT_CUSTOMER = "Tell the customer this is bullshit and we will not refund them."
#: First half of U+1F44D, with no second half after it. Named for what it is,
#: not for a severity: everything else here is named for one.
LONE_SURROGATE = chr(0xD83D)


@pytest.fixture(autouse=True)
def _clear_config(monkeypatch, tmp_path):
    """No ambient API key: ``decide()`` has to take the offline path. No ambient
    rules either, and a fresh rule cache, so each test screens its own rules."""
    for name in (
        "COGNEXUS_API_KEY",
        "MYAPP_API_KEY",
        "COGNEXUS_POLICY_RULES_JSON",
        "COGNEXUS_POLICY_RULES_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    from artzain import cloud

    # No credentials profile either: the path names no file.
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp_path / "no-profile.toml"))
    cloud.configure(api_key=None, base_url=None)
    # The loaded list is cached for the process; monkeypatch restores it.
    monkeypatch.setattr(_helpers, "_policy_rules_cache", None)
    yield
    cloud.configure(api_key=None, base_url=None)


def _rule(rule_id: str, title: str, pattern: str, severity: str) -> ClientPolicyRule:
    return ClientPolicyRule(
        rule_id=rule_id,
        title=title,
        summary=f"{title}.",
        category="acceptable_use",
        agent="compliance_monitor",
        violation_patterns=(pattern,),
        severity=severity,
    )


def _matches_anything(rule_id: str, title: str, severity: str) -> ClientPolicyRule:
    """A rule whose pattern matches any text that has a character in it."""
    return _rule(rule_id, title, ".", severity)


def _decide(monkeypatch, rules: list[ClientPolicyRule], payload: str, **kwargs) -> dict:
    """``decide()`` offline with *rules* configured, so that they are screened
    ahead of the built-in conduct rules."""
    monkeypatch.setenv(
        "COGNEXUS_POLICY_RULES_JSON", json.dumps([r.to_dict() for r in rules])
    )
    return decide(action="send_email", target="crm:1", payload=payload, **kwargs)


def _policy_vote(decision: dict) -> dict:
    return next(
        v for v in decision["contributing_agents"] if v["name"] == "policy-enforcement"
    )


def test_the_findings_cap_keeps_the_conduct_finding_that_denied(monkeypatch):
    """Eight matching low rules used to push the critical conduct finding past
    the cap, and ``decide()`` then headed the deny with a low rule."""
    rules = [_matches_anything(f"LOW-{i}", f"Low {i}", "low") for i in range(8)]

    out = _decide(monkeypatch, rules, PROFANITY_AT_CUSTOMER, kind="user_input")
    vote = _policy_vote(out)

    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert vote["findings"] == [
        "CONDUCT-PROFANITY-CLIENT: Professional conduct with clients",
        *[f"LOW-{i}: Low {i}" for i in range(7)],
    ]
    assert out["outcome"] == "deny"
    assert out["reasons"] == [
        "policy-enforcement (critical): "
        "CONDUCT-PROFANITY-CLIENT: Professional conduct with clients"
    ]


def test_the_vote_orders_its_findings_by_severity(monkeypatch):
    """Most severe first, and findings of one severity in the order they were
    evaluated, so which of them the cap drops does not turn on where a rule sits
    in the rule list."""
    rules = [
        _matches_anything("LOW-A", "Low A", "low"),
        _matches_anything("HIGH-A", "High A", "high"),
        _matches_anything("MED-A", "Med A", "medium"),
        _matches_anything("LOW-B", "Low B", "low"),
        _matches_anything("HIGH-B", "High B", "high"),
        _matches_anything("CRIT-A", "Crit A", "critical"),
    ]

    vote = _policy_vote(
        _decide(monkeypatch, rules, "The quarterly report is attached.", kind="user_input")
    )

    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert vote["findings"] == [
        "CRIT-A: Crit A",
        "HIGH-A: High A",
        "HIGH-B: High B",
        "MED-A: Med A",
        "LOW-A: Low A",
        "LOW-B: Low B",
    ]


def test_the_unpaired_surrogate_finding_still_heads_the_vote(monkeypatch):
    """The evaluator reports an unpaired surrogate first, whatever else matched:
    the rules cannot say what they read. It is critical, and the sort is stable,
    so it stays ahead of a critical conduct finding."""
    payload = json.dumps(
        {"tool": "send_email", "arguments": {"body": PROFANITY_AT_CUSTOMER + LONE_SURROGATE}},
        ensure_ascii=False,
    )
    rules = [_matches_anything(f"LOW-{i}", f"Low {i}", "low") for i in range(8)]

    out = _decide(monkeypatch, rules, payload, kind="tool_call")
    vote = _policy_vote(out)

    assert (vote["verdict"], vote["severity"]) == ("deny", "critical")
    assert vote["findings"] == [
        f"{UNPAIRED_SURROGATE_RULE_ID}: Text is not valid Unicode",
        "CONDUCT-PROFANITY-CLIENT: Professional conduct with clients",
        *[f"LOW-{i}: Low {i}" for i in range(6)],
    ]
    assert out["outcome"] == "deny"
    assert (
        f"policy-enforcement (critical): {UNPAIRED_SURROGATE_RULE_ID}: "
        "Text is not valid Unicode"
    ) in out["reasons"]
