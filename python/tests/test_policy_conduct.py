"""Conduct and secret-safety policy tests."""

from artzain.policy_enforcement import (
    PolicyEnforcementEvaluator,
    builtin_conduct_rules,
    contains_likely_secrets,
    evaluate_conduct,
)
from artzain.policy_enforcement import ClientPolicyRule


def test_excludes_api_key_blob() -> None:
    blob = "STRIPE_API_KEY=sk_live_abc123 GEMINI_API_KEY=xyz"
    assert contains_likely_secrets(blob)


def test_conduct_profanity_toward_client() -> None:
    findings = evaluate_conduct(
        "This client is a fucking nightmare and I hate working with them."
    )
    assert findings
    assert findings[0].rule_id == "CONDUCT-PROFANITY-CLIENT"


def test_evaluator_merges_conduct_with_rules() -> None:
    rules = [
        ClientPolicyRule(
            rule_id="X",
            title="Pricing",
            summary="No pricing commitments without approval.",
            category="acceptable_use",
            agent="compliance_monitor",
            violation_patterns=(r"guarantee.{0,40}pricing",),
            severity="high",
        ),
    ] + list(builtin_conduct_rules())
    report = PolicyEnforcementEvaluator().evaluate(
        "You are an idiot, client.",
        rules,
    )
    assert report.has_violations
