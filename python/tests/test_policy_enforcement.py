"""Tests for client policy enforcement."""

from __future__ import annotations

from artzain.policy_enforcement import (
    ClientPolicyRule,
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
