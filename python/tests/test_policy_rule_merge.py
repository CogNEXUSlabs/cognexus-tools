"""The rule list screened against holds the built-in conduct rules themselves.

``load_client_policy_rules`` and ``screen_client_policy`` merge the built-in
conduct rules into the rules they were given. A rule of the caller's that reuses
a conduct rule's id used to keep the built-in rule out of that list, even when it
carried no patterns of its own and was therefore a copy of it. The list is what
``load_client_policy_rules`` returns to a caller that displays or re-ships the
active rules, and its length is the ``rules_checked`` of the report and of the
audit row, so a copy that had drifted from the built-in rule stood in for it
there.

The merge now follows ``_with_conduct_rules``, as the platform's decision engine
does: a patternless same-id rule is dropped for the built-in rule, and one with
patterns is the caller's own rule, listed under ``<id>/tenant`` beside the
built-in rule so that a report tells the two apart.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from artzain import _helpers
from artzain._helpers import load_client_policy_rules, screen_client_policy
from artzain.policy_enforcement import ClientPolicyRule, builtin_conduct_rules

BUILTIN_IDS = ["CONDUCT-PROFANITY-CLIENT", "CONDUCT-HARASSMENT"]

#: A copy of a built-in conduct rule that has drifted from it: no patterns of its
#: own, but its own title, summary and severity. Rule sets migrated from
#: document-derived rules carry such copies.
DRIFTED_COPY = {
    "rule_id": "CONDUCT-HARASSMENT",
    "title": "Respectful communication (informational)",
    "summary": "Please keep business communications respectful.",
    "category": "hr_policy",
    "agent": "compliance_monitor",
    "severity": "low",
}

#: A rule of the caller's own under a conduct rule's id: it carries patterns, so
#: it says something the built-in rule does not and applies as it is written.
OWN_RULE = ClientPolicyRule(
    rule_id="CONDUCT-HARASSMENT",
    title="No slang in customer email",
    summary="Write 'widget assembly', not 'widget thingy'.",
    category="hr_policy",
    agent="compliance_monitor",
    violation_patterns=(r"\bwidget thingy\b",),
    severity="medium",
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Any:
    """No rules, key or audit directory from the environment, and a fresh cache."""
    for name in (
        "COGNEXUS_POLICY_RULES_JSON",
        "COGNEXUS_POLICY_RULES_PATH",
        "COGNEXUS_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(tmp_path))
    from artzain import cloud, credentials

    monkeypatch.setattr(credentials, "profile_api_key", lambda: None)
    cloud.configure(api_key=None, base_url=None)
    # The loaded list is cached for the process; monkeypatch restores it.
    monkeypatch.setattr(_helpers, "_policy_rules_cache", None)
    yield
    cloud.configure(api_key=None, base_url=None)


def _listed(rules: list[ClientPolicyRule]) -> list[tuple[str, str, str]]:
    return [(r.rule_id, r.title, r.severity) for r in rules]


@pytest.mark.parametrize("rule_id", BUILTIN_IDS)
def test_a_patternless_copy_is_dropped_for_the_built_in_rule(
    monkeypatch: pytest.MonkeyPatch, rule_id: str
) -> None:
    """``load_client_policy_rules`` is public: what it returns is the built-in rule.

    Every conduct id, since the copy is dropped for whichever rule holds it.
    """
    copy = dict(DRIFTED_COPY, rule_id=rule_id)
    monkeypatch.setenv("COGNEXUS_POLICY_RULES_JSON", json.dumps([copy]))
    builtin = {r.rule_id: r for r in builtin_conduct_rules()}[rule_id]

    rules = load_client_policy_rules(force_refresh=True)

    assert _listed(rules) == _listed(builtin_conduct_rules())
    listed = {r.rule_id: r for r in rules}[rule_id]
    assert (listed.title, listed.summary, listed.severity) == (
        builtin.title,
        builtin.summary,
        builtin.severity,
    )
    assert copy["title"] not in [r.title for r in rules]


def test_a_rule_with_patterns_is_listed_beside_the_built_in_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The caller's rule applies as it is written, under ``<id>/tenant``."""
    monkeypatch.setenv("COGNEXUS_POLICY_RULES_JSON", json.dumps([OWN_RULE.to_dict()]))

    rules = load_client_policy_rules(force_refresh=True)

    assert [r.rule_id for r in rules] == ["CONDUCT-HARASSMENT/tenant"] + BUILTIN_IDS
    own = rules[0]
    assert (own.title, own.summary, own.severity, own.violation_patterns) == (
        OWN_RULE.title,
        OWN_RULE.summary,
        OWN_RULE.severity,
        OWN_RULE.violation_patterns,
    )


def test_the_list_the_caller_passed_is_never_modified() -> None:
    given = [OWN_RULE, ClientPolicyRule.from_dict(DRIFTED_COPY)]
    before = list(given)

    screen_client_policy("", source="unit-test", rules=given)

    assert given == before
    assert [r.rule_id for r in given] == ["CONDUCT-HARASSMENT", "CONDUCT-HARASSMENT"]
    assert OWN_RULE.rule_id == "CONDUCT-HARASSMENT"


def test_merging_an_already_merged_list_is_the_same_list() -> None:
    """``screen_client_policy`` merges the cached list, which is already merged.

    It holds because the built-in rules carry no patterns of their own: each is
    dropped as a copy of itself and appended again unchanged. Imported here so
    that the cases above still collect against a module without the helper.
    """
    from artzain._helpers import _with_conduct_rules

    assert not any(r.violation_patterns for r in builtin_conduct_rules())

    once = _with_conduct_rules([OWN_RULE])

    assert _with_conduct_rules(once) == once
    assert _with_conduct_rules(_with_conduct_rules(once)) == once


def test_the_rules_screened_are_counted_once() -> None:
    """``rules_checked`` on the report and on the audit row: three rules, not two.

    An empty text is not screened, so the report carries the count alone.
    """
    report = screen_client_policy("", source="unit-test", rules=[OWN_RULE])
    assert report.rules_checked == 3

    rows: list[dict[str, Any]] = []
    screen_client_policy(
        "The widget assembly ships on Tuesday.",
        source="unit-test",
        rules=[OWN_RULE],
        on_event=rows.append,
    )
    assert [row["rules_checked"] for row in rows] == [3]


def test_the_cached_list_is_not_merged_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    """Screening with no ``rules=`` re-merges the cached list, which changes nothing."""
    assert [r.rule_id for r in load_client_policy_rules(force_refresh=True)] == BUILTIN_IDS
    assert screen_client_policy("", source="unit-test").rules_checked == 2

    monkeypatch.setenv("COGNEXUS_POLICY_RULES_JSON", json.dumps([OWN_RULE.to_dict()]))
    load_client_policy_rules(force_refresh=True)

    assert screen_client_policy("", source="unit-test").rules_checked == 3
