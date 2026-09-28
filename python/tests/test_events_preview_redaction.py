"""The audit preview must be redacted, as the module says it is.

``events`` promises "No raw user text is stored -- only a short redacted
preview and a SHA-256 hash", but ``_redact_preview`` only collapsed whitespace
and cut to 96 characters, so a prompt of 96 characters or fewer was written
verbatim -- twice, under ``preview`` and ``user_prompt`` -- into the JSONL log
and POSTed to the dashboard. The engine's writer already runs the checksum
validated identifiers and ``key=value`` secrets out of the preview
(``security/prompt_defense_events.redact_preview``, open-items 9.26) and emits
no ``user_prompt`` twin; these tests hold the SDK to the same record.

``cloud._redact_prompt_preview`` was a fourth copy of the same truncate-only
helper, and ``post_generation_outcome`` says of its ``prompt`` argument that
"Only a redacted preview is sent", so an identifier in a prompt left the
machine on every event that carried one. It now shares the one implementation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import artzain
import artzain.cloud as cloud
from artzain.cloud import configure
from artzain.events import record_policy_enforcement_event, record_prompt_defense_event
from artzain.kill_switch import clear_run
from artzain.policy_enforcement import PolicyEnforcementReport
from artzain.prompt_injection import DetectionResult, ThreatLevel

_CARD = "4111111111111111"
_SSN = "536 22 1948"


def _clean() -> DetectionResult:
    return DetectionResult(
        is_injection=False,
        threat_level=ThreatLevel.NONE,
        injection_type=None,
        confidence=0.0,
        explanation="No injection patterns detected",
    )


def _record(text: str, tmp_path, monkeypatch) -> dict:
    """One prompt-defense record, as written to JSONL and handed to on_event."""
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(tmp_path))
    rows: list[dict] = []
    record_prompt_defense_event(
        kind="prompt_injection",
        surface="user_input",
        source="test.preview",
        result=_clean(),
        enforcement_action="allowed",
        text=text,
        on_event=rows.append,
    )
    log = tmp_path / "prompt_defense_events.jsonl"
    written = [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert rows[0]["preview"] == written[-1]["preview"], "on_event and JSONL disagree"
    return rows[0]


def test_a_validated_identifier_is_redacted(tmp_path, monkeypatch):
    record = _record(f"My card is {_CARD} and my ssn is {_SSN}.", tmp_path, monkeypatch)
    assert "[REDACTED-CARD]" in record["preview"]
    assert "[REDACTED-SSN]" in record["preview"]
    assert _CARD not in record["preview"]
    assert _SSN not in record["preview"]


def test_a_key_value_secret_is_redacted(tmp_path, monkeypatch):
    record = _record("use api_key=sk_live_51H8xQ2abcdef to call it", tmp_path, monkeypatch)
    assert "[REDACTED]" in record["preview"]
    assert "sk_live_51H8xQ2abcdef" not in record["preview"]


def test_an_identifier_straddling_the_cut_is_redacted(tmp_path, monkeypatch):
    # The card starts inside the 96-character preview and runs past its end;
    # cutting first would leave its leading digits in the record.
    lead = "a" * 88
    record = _record(f"{lead} {_CARD} tail", tmp_path, monkeypatch)
    assert "4111" not in record["preview"]


def test_the_full_text_hash_still_covers_the_whole_input(tmp_path, monkeypatch):
    import hashlib

    text = f"My card is {_CARD}."
    record = _record(text, tmp_path, monkeypatch)
    assert record["input_sha256"] == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_text_holding_no_identifier_is_still_an_excerpt(tmp_path, monkeypatch):
    # Redaction masks identifiers and secrets; it does not make the preview
    # unreadable, and short benign text is stored as written.
    record = _record("Where is my order?", tmp_path, monkeypatch)
    assert record["preview"] == "Where is my order?"


def test_the_record_has_no_user_prompt_twin(tmp_path, monkeypatch):
    record = _record(f"My card is {_CARD}.", tmp_path, monkeypatch)
    assert "user_prompt" not in record, "the duplicate preview key is retired"
    assert record["preview"]


def test_the_cloud_payload_carries_the_redacted_preview_only(
    monkeypatch, artzain_events_capture, artzain_sync_cloud_threads, tmp_path
):
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(tmp_path))
    cloud._session_logged = False
    configure(api_key="k", base_url="https://example.com")
    try:
        record_prompt_defense_event(
            kind="prompt_injection",
            surface="user_input",
            source="test.cloud",
            result=_clean(),
            enforcement_action="allowed",
            text=f"My card is {_CARD}.",
        )
        posted = [b for b in artzain_events_capture if b.get("event_type") == "prompt_defense"]
        assert posted, "expected a prompt_defense POST"
        payload = posted[-1]["payload"]
        assert "[REDACTED-CARD]" in payload["preview"]
        assert _CARD not in json.dumps(posted[-1])
        assert "user_prompt" not in payload
    finally:
        cloud._session_logged = False
        configure(api_key=None, base_url=None)


def test_the_policy_record_is_redacted_the_same_way(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(tmp_path))
    rules = [artzain.ClientPolicyRule.from_dict({
        "rule_id": "CPR-cards",
        "title": "No card numbers in replies",
        "summary": "Never quote a customer's card number back to them.",
        "violation_patterns": [r"card is"],
        "severity": "high",
    })]
    rows: list[dict] = []
    artzain.screen_client_policy(
        f"My card is {_CARD}.", source="test.policy", rules=rules, on_event=rows.append
    )
    assert rows, "screen_client_policy wrote no audit row"
    assert "[REDACTED-CARD]" in rows[0]["preview"]
    assert _CARD not in json.dumps(rows[0])
    assert "user_prompt" not in rows[0]


def test_the_docstrings_describe_what_the_preview_holds():
    import artzain.events as events

    module_doc = " ".join((events.__doc__ or "").split()).lower()
    arg_doc = " ".join((record_prompt_defense_event.__doc__ or "").split()).lower()
    for name, doc in (("module", module_doc), ("text arg", arg_doc)):
        for claim in ("no raw user text is stored", "never written to disk"):
            assert claim not in doc, f"{name} doc keeps the absolute claim {claim!r}"
    assert "redact" in module_doc
    assert "96" in module_doc, "the module doc does not say how much text the preview holds"
    assert "redact" in arg_doc


def test_the_cloud_prompt_preview_shares_the_redaction():
    out = cloud._redact_prompt_preview(f"My card is {_CARD}.")
    assert "[REDACTED-CARD]" in out
    assert _CARD not in out


def test_a_generation_outcome_sends_a_redacted_prompt(
    monkeypatch, artzain_events_capture, artzain_sync_cloud_threads
):
    cloud._session_logged = False
    monkeypatch.setattr(cloud, "_session_user_prompt", None)
    configure(api_key="k", base_url="https://example.com")
    try:
        artzain.post_generation_outcome(
            outcome="passed", reason="ok", prompt=f"My card is {_CARD}.", tokens_in=7
        )
        posted = [b for b in artzain_events_capture if b.get("event_type") == "generation"]
        assert posted, "expected a generation POST"
        assert "[REDACTED-CARD]" in posted[-1]["payload"]["user_prompt"]
        assert _CARD not in json.dumps(posted[-1])
    finally:
        cloud._session_logged = False
        configure(api_key=None, base_url=None)


def test_the_session_prompt_reaches_events_redacted(
    monkeypatch, artzain_events_capture, artzain_sync_cloud_threads
):
    # A later event with no prompt of its own carries the noted session prompt;
    # it must be redacted too.
    cloud._session_logged = False
    monkeypatch.setattr(cloud, "_session_user_prompt", None)
    configure(api_key="k", base_url="https://example.com")
    try:
        cloud.note_session_user_prompt(f"My card is {_CARD}.")
        cloud.post_sdk_event("unit_ping", payload={"n": 1})
        posted = [b for b in artzain_events_capture if b.get("event_type") == "unit_ping"]
        assert posted, "expected the ping POST"
        assert "[REDACTED-CARD]" in posted[-1]["payload"]["user_prompt"]
        assert _CARD not in json.dumps(posted[-1])
    finally:
        cloud._session_logged = False
        configure(api_key=None, base_url=None)


@pytest.fixture
def cloud_on(monkeypatch, tmp_path, artzain_events_capture, artzain_sync_cloud_threads):
    """Events posted to a fake platform, with no session prompt noted yet."""
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(tmp_path))
    monkeypatch.delenv("COGNEXUS_PROMPT_DEFENSE_CLOUD_PASSES", raising=False)
    monkeypatch.setattr(cloud, "_session_user_prompt", None)
    monkeypatch.setattr(cloud, "_session_logged", False)
    configure(api_key="cnx_test_key_not_real", base_url="https://example.test")
    return artzain_events_capture


def _posted(capture: list[dict], event_type: str) -> dict:
    bodies = [b for b in capture if b.get("event_type") == event_type]
    assert bodies, f"expected a {event_type} POST"
    return bodies[-1]


@pytest.mark.parametrize("kind", ["prompt_defense", "policy_enforcement"])
def test_a_noted_prompt_does_not_stand_in_for_the_screened_text(cloud_on, kind):
    # screen_user_input notes each prompt for the events that follow it. The
    # user_prompt twin used to keep it off these rows, and without the twin
    # they must still not be given it: the platform keeps ``user_prompt`` ahead
    # of ``preview``, so the dashboard would show the user's prompt for, say,
    # the model output screened here.
    cloud.note_session_user_prompt("Summarise the attached report")
    text = f"The card on file is {_CARD}."
    if kind == "prompt_defense":
        record_prompt_defense_event(
            kind="prompt_injection",
            surface="model_output",
            source="test.reply",
            result=_clean(),
            enforcement_action="allowed",
            text=text,
        )
    else:
        record_policy_enforcement_event(
            surface="model_output",
            source="test.reply",
            report=PolicyEnforcementReport(violation_count=0, findings=[], rules_checked=0),
            enforcement_action="logged",
            text=text,
        )
    payload = _posted(cloud_on, kind)["payload"]
    assert "user_prompt" not in payload
    assert payload["preview"].startswith("The card on file is [REDACTED-CARD]")


def test_agent_guard_events_still_carry_the_noted_prompt(cloud_on):
    # Only the audit rows above opt out. An agent-guard event's preview is its
    # reason, and the prompt noted for the session still rides along with it.
    cloud.note_session_user_prompt(f"Close my account, card {_CARD}")
    run_id = "run-noted-prompt"
    try:
        artzain.screen_agent_action(
            "DROP TABLE users;", run_id=run_id, agent_id="unit-test", raise_on_critical=False
        )
    finally:
        clear_run(run_id)
    guarded = [
        b for b in cloud_on
        if b.get("event_type") in ("agent_kill_switch", "destructive_action_guard")
    ]
    assert guarded, [b.get("event_type") for b in cloud_on]
    for body in guarded:
        assert "[REDACTED-CARD]" in body["payload"]["user_prompt"]
    for body in cloud_on:
        assert _CARD not in json.dumps(body), body.get("event_type")


def _flat(text: str | None) -> str:
    return " ".join((text or "").split()).lower()


def test_the_readme_and_package_doc_say_what_the_preview_keeps():
    readme_path = Path(__file__).resolve().parents[1] / "README.md"
    readme = _flat(readme_path.read_text(encoding="utf-8"))
    for name, doc in (("artzain", _flat(artzain.__doc__)), ("README.md", readme)):
        for claim in ("no raw", "never written"):
            assert claim not in doc, f"{name} still says {claim!r}"
    notes = readme.split("## security notes", 1)[1]
    assert "96 characters" in notes, "the security notes do not say how much the preview holds"
    assert "stored as written" in notes, "the security notes do not say what stays unmasked"
