"""Conduct and secret-safety policy tests."""

import json

from artzain.policy_enforcement import (
    ClientPolicyRule,
    PolicyEnforcementEvaluator,
    builtin_conduct_rules,
    contains_likely_secrets,
    evaluate_conduct,
)


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


def test_client_context_false_rules_client_words_out() -> None:
    # A caller that knows the client words in a text name no client passes client_context=False.
    text = "This client is a fucking nightmare."
    assert evaluate_conduct(text, client_context=False) == []
    assert evaluate_conduct(text, client_context=True)[0].rule_id == "CONDUCT-PROFANITY-CLIENT"
    # It never adds a client the text does not name.
    assert evaluate_conduct("This is bullshit.", client_context=True) == []
    # Profanity aimed at the reader is a client finding whatever the context.
    assert evaluate_conduct("You idiot, this is bullshit.", client_context=False)[0].severity == "critical"
    report = PolicyEnforcementEvaluator().evaluate(text, builtin_conduct_rules(), client_context=False)
    assert report.findings == []


def test_an_argument_name_does_not_name_a_client() -> None:
    from artzain.tool_call_contract import conduct_client_context, evaluate_tool_call_policy

    # An internal message: read as text, the call's "account" argument would be client context.
    arguments = {"channel": "#eng", "text": "Deploy failed again. WTF is going on?", "account": "acme-prod"}
    payload = json.dumps({"tool": "slack.post_message", "arguments": arguments})
    assert PolicyEnforcementEvaluator().evaluate(payload, builtin_conduct_rules()).findings
    assert conduct_client_context(payload) is False
    assert evaluate_tool_call_policy(PolicyEnforcementEvaluator(), payload, builtin_conduct_rules()).findings == []


def test_a_tool_call_names_a_client_in_its_values() -> None:
    from artzain.tool_call_contract import conduct_client_context, evaluate_tool_call_policy

    arguments = {"to": "jane@example.com", "subject": "For our customer", "body": "This is\nbullshit."}
    payload = json.dumps({"tool": "send_email", "arguments": arguments})
    assert conduct_client_context(payload) is True
    report = evaluate_tool_call_policy(PolicyEnforcementEvaluator(), payload, builtin_conduct_rules())
    assert [f.rule_id for f in report.findings] == ["CONDUCT-PROFANITY-CLIENT"]
    # Text that is not a call is searched as text.
    assert conduct_client_context("This is not JSON") is None
