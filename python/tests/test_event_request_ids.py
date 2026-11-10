"""The correlation id the event helpers send, and a decision id among them."""

from __future__ import annotations

import pytest

import artzain.cloud as cloud
from artzain.cloud import configure, post_generation_outcome
from artzain.events import record_policy_enforcement_event, record_prompt_defense_event
from artzain.policy_enforcement import PolicyEnforcementReport
from artzain.prompt_injection import DetectionResult, ThreatLevel

_DECISION = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

_CLEAN = DetectionResult(
    is_injection=False,
    threat_level=ThreatLevel.NONE,
    injection_type=None,
    confidence=0.0,
    explanation="No injection patterns detected",
)


def _generation(request_id):
    post_generation_outcome(outcome="passed", reason="ok", request_id=request_id,
                            tokens_in=3, tokens_out=4)
    return "generation"


def _prompt_defense(request_id):
    record_prompt_defense_event(
        kind="prompt_injection", surface="user_input", source="test.ids", result=_CLEAN,
        enforcement_action="allowed", text="hello", request_id=request_id,
    )
    return "prompt_defense"


def _policy(request_id):
    record_policy_enforcement_event(
        surface="user_input", source="test.ids",
        report=PolicyEnforcementReport(violation_count=0, findings=[], rules_checked=0),
        enforcement_action="allowed", text="hello", request_id=request_id,
    )
    return "policy_enforcement"


@pytest.fixture
def sent(monkeypatch, artzain_events_capture, artzain_sync_cloud_threads, tmp_path):
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(tmp_path))
    monkeypatch.delenv("COGNEXUS_PROMPT_DEFENSE_CLOUD_PASSES", raising=False)
    cloud._session_logged = False
    configure(api_key="k", base_url="https://example.com")

    def run(helper, request_id):
        event_type = helper(request_id)
        bodies = [b for b in artzain_events_capture if b.get("event_type") == event_type]
        assert bodies, f"no {event_type} event was sent"
        return bodies[-1]["payload"]["request_id"]

    try:
        yield run
    finally:
        cloud._session_logged = False
        configure(api_key=None, base_url=None)


@pytest.mark.parametrize("helper", [_generation, _prompt_defense, _policy])
@pytest.mark.parametrize("given", [_DECISION, _DECISION.lower(), "  " + _DECISION.lower() + " "])
def test_a_decision_id_is_sent_as_the_server_wrote_it(sent, helper, given):
    assert sent(helper, given) == _DECISION


@pytest.mark.parametrize("helper", [_generation, _prompt_defense, _policy])
def test_any_other_id_is_sent_in_lower_case_as_before(sent, helper):
    assert sent(helper, "Order-8812") == "order-8812"
    assert sent(helper, "ABCDEF0123456789ABCDEF0123456789") == "abcdef0123456789abcdef0123456789"
