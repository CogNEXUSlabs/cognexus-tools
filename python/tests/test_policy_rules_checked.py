"""One screening, one ``rules_checked``: the report's and the audit row's.

``screen_client_policy`` merges the built-in conduct rules into the rules it
screens, and records the length of that list on the audit row and on the
report for an empty text. The evaluator counted the conduct rules a second
time on the report for any other text, so a screened text was reported
against two rules more than its audit row recorded.

``rules_checked`` is the length of the rule list screened, on every path.
"""

from __future__ import annotations

from typing import Any

import pytest

from artzain import _helpers
from artzain._helpers import load_client_policy_rules, screen_client_policy
from artzain.policy_enforcement import (
    ClientPolicyRule,
    PolicyEnforcementEvaluator,
    builtin_conduct_rules,
)

#: A rule of the caller's own.
NAMING = ClientPolicyRule(
    rule_id="ACME-naming",
    title="Product names in customer email",
    summary="Write 'widget assembly', not 'widget thingy'.",
    category="acceptable_use",
    agent="compliance_monitor",
    violation_patterns=(r"\bwidget thingy\b",),
    severity="medium",
)

CLEAN = "The widget assembly ships on Tuesday."
FINDING = "The widget thingy ships on Tuesday."
#: An insult aimed at the reader, which the conduct detector reports.
INSULT = "Honestly, you are an idiot for asking that."


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Any:
    """No rules, key or audit directory from the environment, and a fresh cache."""
    for name in (
        "COGNEXUS_POLICY_RULES_JSON",
        "COGNEXUS_POLICY_RULES_PATH",
        "COGNEXUS_API_KEY",
        "MYAPP_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(tmp_path))
    from artzain import cloud

    # No credentials profile either: the path names no file.
    monkeypatch.setenv("COGNEXUS_CREDENTIALS_PATH", str(tmp_path / "no-profile.toml"))
    cloud.configure(api_key=None, base_url=None)
    # The loaded list is cached for the process; monkeypatch restores it.
    monkeypatch.setattr(_helpers, "_policy_rules_cache", None)
    yield
    cloud.configure(api_key=None, base_url=None)


@pytest.mark.parametrize("text", [CLEAN, FINDING], ids=["clean", "finding"])
def test_the_report_counts_the_rules_its_audit_row_records(text: str) -> None:
    rows: list[dict[str, Any]] = []

    report = screen_client_policy(
        text, source="unit-test", rules=[NAMING], on_event=rows.append
    )

    assert report.has_violations is (text == FINDING)
    # The caller's rule and the two built-in conduct rules merged in beside it.
    assert [row["rules_checked"] for row in rows] == [3]
    assert report.rules_checked == 3


def test_an_empty_text_and_a_screened_one_count_alike() -> None:
    assert screen_client_policy("", source="unit-test", rules=[NAMING]).rules_checked == 3
    assert screen_client_policy(CLEAN, source="unit-test", rules=[NAMING]).rules_checked == 3


def test_the_loaded_rules_are_counted_as_they_are_listed() -> None:
    """With no ``rules=``, the loaded list: here the built-in conduct rules alone."""
    listed = load_client_policy_rules(force_refresh=True)
    rows: list[dict[str, Any]] = []

    report = screen_client_policy(CLEAN, source="unit-test", on_event=rows.append)

    assert len(listed) == 2
    assert [row["rules_checked"] for row in rows] == [2]
    assert report.rules_checked == 2


@pytest.mark.parametrize(
    "rules",
    [
        pytest.param([NAMING, *builtin_conduct_rules()], id="merged"),
        pytest.param(builtin_conduct_rules(), id="conduct-only"),
        pytest.param([NAMING], id="own-rules-only"),
    ],
)
def test_the_evaluator_counts_the_list_it_is_handed(rules: list[ClientPolicyRule]) -> None:
    """The conduct detector runs beside any non-empty list. It is counted
    through the conduct rules the list holds, not added on top of them."""
    report = PolicyEnforcementEvaluator().evaluate(FINDING, rules)

    assert report.rules_checked == len(rules)


def test_the_conduct_detector_runs_beside_the_callers_own_rules() -> None:
    """A list without the conduct rules is counted as it is, so the count no
    longer shows the detector ran; the finding does."""
    evaluator = PolicyEnforcementEvaluator()

    report = evaluator.evaluate(INSULT, [NAMING])

    assert [(f.rule_id, f.severity) for f in report.findings] == [
        ("CONDUCT-HARASSMENT", "high")
    ]
    assert evaluator.should_block(report) is True
    assert report.rules_checked == 1
