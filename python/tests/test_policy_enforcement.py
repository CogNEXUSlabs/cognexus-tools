"""Tests for client policy enforcement."""

from __future__ import annotations

import re
from unittest import mock

from artzain.policy_enforcement import (
    ClientPolicyRule,
    PolicyEnforcementConfig,
    PolicyEnforcementEvaluator,
    extract_rules_from_document,
    rules_from_context_items,
    violation_patterns_from_sentence,
)


def test_violation_patterns_from_negation() -> None:
    pats = violation_patterns_from_sentence(
        "Customer PII must not exceed 36 months post-churn unless a legal hold applies."
    )
    assert pats


def test_extract_rules_from_hr_doc() -> None:
    body = (
        "Keyword hits: policy (2)\n\n"
        "Employees must not share credentials externally. "
        "Marketing must not commit to custom SLAs without sales leadership approval."
    )
    rules = extract_rules_from_document(
        subject="HR Security Policy 2026.pdf",
        body=body,
        agent="compliance_monitor",
    )
    assert len(rules) >= 1
    assert rules[0].source_refs[0] == "HR Security Policy 2026.pdf"


def test_evaluator_flags_pricing_commitment() -> None:
    rules = [
        ClientPolicyRule(
            rule_id="CPR-test",
            title="No pricing commitments",
            summary="No commitments on pricing without sales leadership approval.",
            category="acceptable_use",
            agent="compliance_monitor",
            violation_patterns=(
                r"(?:commit|guarantee|promise|offer).{0,90}(?:pricing|discount|sla|custom)",
            ),
            severity="high",
        )
    ]
    report = PolicyEnforcementEvaluator().evaluate(
        "I can commit to a 40% discount on enterprise pricing for you.",
        rules,
    )
    assert report.has_violations


def test_evaluator_allows_with_approval_marker() -> None:
    rules = [
        ClientPolicyRule(
            rule_id="CPR-test2",
            title="SLA approval",
            summary="Custom SLAs require sales leadership approval.",
            category="acceptable_use",
            agent="compliance_monitor",
            violation_patterns=(
                r"(?:commit|guarantee|promise|offer).{0,90}(?:pricing|discount|sla|custom)",
            ),
            severity="high",
        )
    ]
    report = PolicyEnforcementEvaluator().evaluate(
        "Custom SLA offered with sales leadership approval documented in ticket #99.",
        rules,
    )
    assert not report.has_violations


_PRICING_RULE = ClientPolicyRule(
    rule_id="CPR-pricing",
    title="No pricing commitments",
    summary="No commitments on pricing without sales leadership approval.",
    category="acceptable_use",
    agent="compliance_monitor",
    violation_patterns=(
        r"(?:commit|guarantee|promise|offer).{0,90}(?:pricing|discount|sla|custom)",
    ),
    severity="high",
)

_FILLER = (
    "Thanks again for the call earlier today; the notes from the "
    "architecture review are attached and the onboarding checklist is "
    "in the shared folder for your team to work through next week. "
) * 3


def test_approval_marker_far_from_match_does_not_suppress() -> None:
    text = "We commit to custom pricing for you. " + _FILLER + "Filed per policy."
    report = PolicyEnforcementEvaluator().evaluate(text, [_PRICING_RULE])
    assert report.violation_count == 1
    assert report.findings[0].rule_id == "CPR-pricing"
    assert not report.findings[0].suppressed_by_approval_marker
    assert report.suppressed == []


def test_approval_marker_adjacent_to_match_suppresses_and_is_recorded() -> None:
    text = "We commit to custom pricing for you per policy."
    report = PolicyEnforcementEvaluator().evaluate(text, [_PRICING_RULE])
    assert report.violation_count == 0
    assert not report.has_violations
    assert len(report.suppressed) == 1
    sup = report.suppressed[0]
    assert sup.rule_id == "CPR-pricing"
    assert sup.suppressed_by_approval_marker
    assert sup.approval_marker == "per policy"


def test_approval_marker_before_match_within_window_suppresses() -> None:
    text = (
        "Approved by sales leadership in ticket #99: we can offer a "
        "10% discount on the renewal."
    )
    report = PolicyEnforcementEvaluator().evaluate(text, [_PRICING_RULE])
    assert not report.has_violations
    assert len(report.suppressed) == 1
    assert report.suppressed[0].approval_marker == "approved by"


def test_approval_window_is_configurable() -> None:
    text = "We commit to custom pricing for you. " + _FILLER + "Filed per policy."
    cfg = PolicyEnforcementConfig(approval_window_chars=10_000)
    report = PolicyEnforcementEvaluator(cfg).evaluate(text, [_PRICING_RULE])
    assert not report.has_violations
    assert len(report.suppressed) == 1


def test_approval_escape_disabled_never_suppresses() -> None:
    text = "We commit to custom pricing for you per policy."
    cfg = PolicyEnforcementConfig(require_approval_escape=False)
    report = PolicyEnforcementEvaluator(cfg).evaluate(text, [_PRICING_RULE])
    assert report.violation_count == 1
    assert report.suppressed == []


def _bundle(n_rules: int, n_patterns: int) -> list[ClientPolicyRule]:
    return [
        ClientPolicyRule.from_dict(
            {
                "rule_id": f"CPR-{i}",
                "title": f"Rule {i}",
                "summary": f"Do not do thing {i}.",
                "category": "acceptable_use",
                "agent": "compliance_monitor",
                "violation_patterns": [
                    rf"thing.{{0,10}}{i}.{{0,10}}variant{j}" for j in range(n_patterns)
                ],
            }
        )
        for i in range(n_rules)
    ]


def test_evaluate_does_not_recompile_rule_patterns() -> None:
    real_compile = re.compile
    with mock.patch("re.compile", wraps=real_compile) as compile_mock:
        rules = _bundle(12, 6)
        evaluator = PolicyEnforcementEvaluator()
        for k in range(5):
            re.purge()  # so the stdlib pattern cache cannot mask recompiles
            report = evaluator.evaluate(f"no match here {k}", rules)
            assert report.violation_count == 0
    assert compile_mock.call_count == 12 * 6


def test_compiled_patterns_are_stable_and_invalid_ones_skipped() -> None:
    rule = ClientPolicyRule.from_dict(
        {
            "rule_id": "CPR-mixed",
            "title": "Mixed",
            "summary": "Do not.",
            "violation_patterns": [r"valid.{0,5}one", r"(unclosed", r"VALID.two"],
        }
    )
    first = rule.compiled_patterns()
    assert first is rule.compiled_patterns()
    assert [p.pattern for p in first] == [r"valid.{0,5}one", r"VALID.two"]
    assert all(p.flags & re.IGNORECASE for p in first)
    assert rule.to_dict()["violation_patterns"] == [
        r"valid.{0,5}one",
        r"(unclosed",
        r"VALID.two",
    ]
    report = PolicyEnforcementEvaluator().evaluate("Valid Two", [rule])
    assert report.violation_count == 1
    assert report.findings[0].matched_pattern == r"VALID.two"
    assert rule == ClientPolicyRule.from_dict(rule.to_dict())
    assert hash(rule) == hash(ClientPolicyRule.from_dict(rule.to_dict()))


_CONTEXT_BODY = (
    "Keyword hits: policy (2)\n\n"
    "Employees must not share credentials externally. "
    "Marketing must not commit to custom SLAs without sales leadership approval."
)


def test_context_item_source_ref_is_the_subject_with_or_without_a_link() -> None:
    # The rule id is derived from the source ref, so the ref must not change
    # with ``metadata.web_link``; the dashboard takes links from the metadata.
    plain = {"subject": "HR Security Policy 2026.pdf", "snippet": _CONTEXT_BODY}
    linked = dict(plain, metadata={"web_link": "https://drive.example.com/d/1"})
    without_link = rules_from_context_items([plain])
    with_link = rules_from_context_items([linked])
    assert len(without_link) >= 1
    assert without_link[0].source_refs == ("HR Security Policy 2026.pdf",)
    assert [(r.rule_id, r.source_refs) for r in without_link] == [
        (r.rule_id, r.source_refs) for r in with_link
    ]


def test_context_item_without_subject_is_cited_as_untitled() -> None:
    rules = rules_from_context_items([{"snippet": _CONTEXT_BODY}])
    assert len(rules) >= 1
    assert rules[0].source_refs == ("(untitled)",)
