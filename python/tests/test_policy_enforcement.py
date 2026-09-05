"""Tests for client policy enforcement."""

from __future__ import annotations

from artzain.policy_enforcement import (
    ClientPolicyRule,
    PolicyEnforcementConfig,
    PolicyEnforcementEvaluator,
    extract_rules_from_document,
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
