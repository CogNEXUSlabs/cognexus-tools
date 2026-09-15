"""Tests for client policy enforcement."""

from __future__ import annotations

import re
from unittest import mock

import pytest

import artzain.policy_enforcement as policy_enforcement
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


# Approval markers: each match of a pattern is approved by a marker near it,
# markers compare in lower case, and a bounded number of matches of one
# pattern can be approved. The engine suite holds the adversarial cases.

#: One approved commitment per line; ``.`` stops a match at the line end.
_APPROVED_LINE = "Per policy we offer a discount on this renewal.\n"
#: U+0130, capital I with dot above: its lower case is two characters.
_DOTTED_I = chr(0x130)
#: Small and final small sigma. ``str.lower()`` turns a capital sigma into the
#: final form at the end of a word and the small form elsewhere.
_SIGMA, _FINAL_SIGMA = chr(0x3C3), chr(0x3C2)
#: "EGKRISIS" (approval) in Greek capitals, and as a lower-case marker that
#: ends in the final sigma.
_GREEK_APPROVAL = "".join(map(chr, (0x395, 0x393, 0x39A, 0x3A1, 0x399, 0x3A3, 0x397, 0x3A3)))
_GREEK_MARKER = "".join(map(chr, (0x3B5, 0x3B3, 0x3BA, 0x3C1, 0x3B9, 0x3C3, 0x3B7, 0x3C2)))


def test_every_match_approved_is_one_suppression_with_the_first_marker() -> None:
    # The first match is approved "per policy"; the later ones "approved by",
    # which comes first in the configured markers.
    later = "We offer a discount on this renewal, approved by legal.\n"
    text = _APPROVED_LINE + (_FILLER + later) * 60
    report = PolicyEnforcementEvaluator().evaluate(text, [_PRICING_RULE])
    assert not report.has_violations
    assert len(report.suppressed) == 1
    sup = report.suppressed[0]
    assert sup.rule_id == "CPR-pricing"
    assert sup.suppressed_by_approval_marker
    assert sup.approval_marker == "per policy"


@pytest.mark.parametrize(
    ("text", "approved"),
    [
        ("per policy" + " " * 150 + "offer discount", True),
        ("per policy" + " " * 151 + "offer discount", False),
        ("offer discount" + " " * 150 + "per policy", True),
        ("offer discount" + " " * 151 + "per policy", False),
    ],
    ids=["before-at-edge", "before-past-edge", "after-at-edge", "after-past-edge"],
)
def test_the_window_edges_are_exact(text: str, approved: bool) -> None:
    # The match is "offer discount"; the window is 160 characters on each side.
    report = PolicyEnforcementEvaluator().evaluate(text, [_PRICING_RULE])
    assert report.has_violations is not approved
    assert len(report.suppressed) == int(approved)


def test_marker_positions_belong_to_the_text_being_screened() -> None:
    # One evaluator screens many texts (screen_client_policy keeps one): a
    # marker in an earlier text must not approve a match in a later one.
    evaluator = PolicyEnforcementEvaluator()
    earlier = evaluator.evaluate("Per policy, the quote can offer a discount.", [_PRICING_RULE])
    later = evaluator.evaluate("We commit to a custom SLA for this account.", [_PRICING_RULE])
    assert not earlier.has_violations
    assert [f.rule_id for f in later.findings] == ["CPR-pricing"]
    assert evaluator.should_block(later)


@pytest.mark.parametrize("marker", [_GREEK_MARKER, _GREEK_MARKER.replace(_FINAL_SIGMA, _SIGMA)])
@pytest.mark.parametrize("prefix", ["", _DOTTED_I + " " * 400], ids=["plain", "dotted-I-far-before"])
def test_a_sigma_matches_in_either_form_whatever_else_the_text_holds(marker: str, prefix: str) -> None:
    # Lower-casing picks the final or the small sigma from the neighbouring
    # letters, and a text holding a dotted capital I is lower-cased one
    # character at a time; neither may decide whether a marker matches.
    cfg = PolicyEnforcementConfig(approval_markers=(marker,))
    text = prefix + "We offer a discount, " + _GREEK_APPROVAL + "."
    report = PolicyEnforcementEvaluator(cfg).evaluate(text, [_PRICING_RULE])
    assert not report.has_violations
    assert [f.approval_marker for f in report.suppressed] == [marker]


def test_markers_that_are_not_text_are_ignored() -> None:
    cfg = PolicyEnforcementConfig(approval_markers=(123, None, b"per policy", "", "Per Policy"))
    report = PolicyEnforcementEvaluator(cfg).evaluate(
        "We commit to custom pricing for you per policy.", [_PRICING_RULE]
    )
    assert not report.has_violations
    assert [f.approval_marker for f in report.suppressed] == ["per policy"]


def test_with_no_window_the_marker_must_be_inside_the_match() -> None:
    cfg = PolicyEnforcementConfig(approval_window_chars=0)
    inside = PolicyEnforcementEvaluator(cfg).evaluate(
        "We commit, per policy, to custom pricing.", [_PRICING_RULE]
    )
    before = PolicyEnforcementEvaluator(cfg).evaluate(
        "Per policy: we commit to custom pricing.", [_PRICING_RULE]
    )
    assert not inside.has_violations
    assert len(inside.suppressed) == 1
    assert [f.rule_id for f in before.findings] == ["CPR-pricing"]


def test_overlapping_occurrences_of_a_marker_count() -> None:
    # Only the occurrence of "abab" that starts at index 2 lies inside the
    # match (window 0); it overlaps the one at index 0.
    rule = ClientPolicyRule(
        rule_id="CPR-ab",
        title="ab",
        summary="Needs approval.",
        category="general",
        agent="compliance_monitor",
        violation_patterns=(r"(?<=ab)abab",),
        severity="high",
    )
    cfg = PolicyEnforcementConfig(approval_markers=("abab",), approval_window_chars=0)
    report = PolicyEnforcementEvaluator(cfg).evaluate("ababab", [rule])
    assert not report.has_violations
    assert [f.approval_marker for f in report.suppressed] == ["abab"]


def test_a_pattern_with_more_matches_than_can_be_approved_is_a_finding() -> None:
    cfg = PolicyEnforcementConfig(approval_max_matches=3)
    within = PolicyEnforcementEvaluator(cfg).evaluate(_APPROVED_LINE * 3, [_PRICING_RULE])
    past = PolicyEnforcementEvaluator(cfg).evaluate(_APPROVED_LINE * 4, [_PRICING_RULE])
    assert not within.has_violations
    assert len(within.suppressed) == 1
    assert [f.rule_id for f in past.findings] == ["CPR-pricing"]
    assert past.suppressed == []


def test_the_default_approves_a_hundred_matches_of_a_pattern() -> None:
    assert PolicyEnforcementConfig().approval_max_matches == 100
    evaluator = PolicyEnforcementEvaluator()
    assert not evaluator.evaluate(_APPROVED_LINE * 100, [_PRICING_RULE]).has_violations
    assert evaluator.evaluate(_APPROVED_LINE * 101, [_PRICING_RULE]).has_violations


def _approval_rules() -> list[ClientPolicyRule]:
    return [
        ClientPolicyRule(
            rule_id=f"CPR-{i}",
            title=f"Rule {i}",
            summary="No commitments on pricing without sales leadership approval.",
            category="acceptable_use",
            agent="compliance_monitor",
            violation_patterns=tuple(rf"offer.{{0,{20 + j}}}discount" for j in range(6)),
            severity="high",
        )
        for i in range(80)
    ]


def test_marker_positions_are_found_once_per_text() -> None:
    rules = _approval_rules()
    with mock.patch.object(
        policy_enforcement, "_ApprovalMarkers", wraps=policy_enforcement._ApprovalMarkers
    ) as markers:
        report = PolicyEnforcementEvaluator().evaluate(_APPROVED_LINE * 90, rules)
    assert not report.has_violations
    assert len(report.suppressed) == 80 * 6
    assert markers.call_count == 1


def test_no_marker_search_without_a_match_of_an_approval_rule() -> None:
    with mock.patch.object(
        policy_enforcement, "_ApprovalMarkers", wraps=policy_enforcement._ApprovalMarkers
    ) as markers:
        report = PolicyEnforcementEvaluator().evaluate(_FILLER + " per policy", _approval_rules())
    assert not report.has_violations
    assert markers.call_count == 0


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
