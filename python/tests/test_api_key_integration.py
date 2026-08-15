"""API-key integration tests against artzain screening layers and cloud ingest.

Requires ``COGNEXUS_API_KEY`` (and optionally ``MYAPP_API_KEY``). Cloud POSTs are captured
via a test ``urllib`` shim — set ``COGNEXUS_API_BASE_URL`` and pass a real ``base_url``
only when using ``configure()`` yourself outside these tests.

Run::

    cd pypi-package
    export PYTHONPATH=src
    export COGNEXUS_API_KEY="your-dashboard-api-key"
    python -m pytest tests/test_api_key_integration.py -v

Optional local inference smoke (pulls ``Qwen/Qwen3-4B-Instruct-2507``; heavy)::

    pip install torch transformers accelerate
    export COGNEXUS_RUN_MODEL_SMOKE=1
    python -m pytest tests/test_api_key_integration.py::test_optional_qwen_smoke_inference -v

Static defense scenarios follow every vector in :data:`artzain.prompt_defense.VECTOR_COUNT`
(currently 15). OWASP coverage pairs **LLM01–LLM10 (2025)** with **ASI01–ASI10 (agentic)**
for twenty guideline-aligned checks.
"""

from __future__ import annotations

import os
import uuid

import pytest

from artzain import (
    AgentKilledError,
    InjectionType,
    augment_system_prompt,
    evaluate_system_prompt,
    maybe_log_prompt_defense,
    post_sdk_event,
    reset_detectors,
    screen_agent_action,
    screen_external_content,
    screen_user_input,
)
from artzain.cloud import configure as cloud_configure
from artzain.destructive_action_guard import ActionSeverity, screen_action
from artzain.kill_switch import _reset_for_tests

pytestmark = pytest.mark.skipif(
    not (os.environ.get("COGNEXUS_API_KEY") or os.environ.get("MYAPP_API_KEY")),
    reason="Set COGNEXUS_API_KEY (or MYAPP_API_KEY) to run integration tests.",
)

from tests.fixtures import threat_prompts as tp  # noqa: E402 — after skipif


@pytest.fixture
def integration_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    artzain_events_capture,
):
    """Configure artzain with env API key and urllib-captured cloud payloads."""

    events_dir = tmp_path / "events"
    events_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("COGNEXUS_PROMPT_DEFENSE_EVENTS_DIR", str(events_dir))

    captured = artzain_events_capture
    api_key = (os.environ.get("COGNEXUS_API_KEY") or os.environ.get("MYAPP_API_KEY") or "").strip()
    assert api_key

    cloud_configure(api_key=api_key, base_url="http://127.0.0.1:1")
    reset_detectors()
    _reset_for_tests()

    from types import SimpleNamespace

    yield SimpleNamespace(captured=captured, events_dir=events_dir)

    cloud_configure(api_key=None, base_url=None)


def _log_suite_event(test_id: str, **payload: object) -> None:
    """Mirror structured outcomes into the dashboard Event Logs."""

    post_sdk_event(
        "integration_suite_result",
        source="pypi_sdk",
        level="info",
        title=f"artzain.integration.{test_id}",
        payload={"test_id": test_id, **payload},
    )


def _assert_cloud_posts(ctx: object) -> None:
    assert ctx.captured, "expected POST /api/events from artzain.cloud.post_sdk_event"


# --- Static defense vectors (themes aligned with prompt_defense._RULES) ----------


def test_defense_role_escape(integration_env) -> None:
    r = screen_user_input(tp.DEFENSE_ROLE_ESCAPE, source="integration.defense_role_escape")
    assert r.is_injection and r.injection_type == InjectionType.ROLE_PLAY
    _log_suite_event("defense_role_escape", outcome="intercepted", threat=r.threat_level.value)
    _assert_cloud_posts(integration_env)


def test_defense_instruction_override(integration_env) -> None:
    r = screen_user_input(
        tp.DEFENSE_INSTRUCTION_OVERRIDE,
        source="integration.defense_instruction_override",
    )
    assert r.is_injection and r.injection_type == InjectionType.DIRECT_OVERRIDE
    _log_suite_event(
        "defense_instruction_override",
        outcome="intercepted",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_defense_data_leakage(integration_env) -> None:
    r = screen_user_input(tp.DEFENSE_DATA_LEAKAGE, source="integration.defense_data_leakage")
    assert r.is_injection and r.injection_type == InjectionType.CONTEXT_MANIPULATION
    _log_suite_event("defense_data_leakage", outcome="intercepted", threat=r.threat_level.value)
    _assert_cloud_posts(integration_env)


def test_defense_output_manipulation(integration_env) -> None:
    r = screen_user_input(
        tp.DEFENSE_OUTPUT_MANIPULATION,
        source="integration.defense_output_manipulation",
    )
    assert r.is_injection and r.injection_type == InjectionType.DELIMITER_ATTACK
    _log_suite_event(
        "defense_output_manipulation",
        outcome="intercepted",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_defense_multilang_bypass(integration_env) -> None:
    r = screen_user_input(
        tp.DEFENSE_MULTILANG_BYPASS,
        source="integration.defense_multilang_bypass",
    )
    assert r.is_injection
    _log_suite_event(
        "defense_multilang_bypass",
        outcome="intercepted",
        threat=r.threat_level.value,
        type_=r.injection_type.value if r.injection_type else None,
    )
    _assert_cloud_posts(integration_env)


def test_defense_unicode_attack(integration_env) -> None:
    r = screen_user_input(tp.DEFENSE_UNICODE_ATTACK, source="integration.defense_unicode_attack")
    assert r.is_injection and r.injection_type == InjectionType.TOKEN_SMUGGLING
    _log_suite_event("defense_unicode_attack", outcome="intercepted", threat=r.threat_level.value)
    _assert_cloud_posts(integration_env)


def test_defense_context_overflow(integration_env) -> None:
    r = screen_user_input(
        tp.DEFENSE_CONTEXT_OVERFLOW,
        source="integration.defense_context_overflow",
    )
    assert r.is_injection
    _log_suite_event(
        "defense_context_overflow",
        outcome="intercepted",
        threat=r.threat_level.value,
        type_=r.injection_type.value if r.injection_type else None,
    )
    _assert_cloud_posts(integration_env)


def test_defense_indirect_injection(integration_env) -> None:
    r = screen_external_content(
        tp.DEFENSE_INDIRECT_INJECTION,
        source="integration.defense_indirect_injection",
    )
    assert r.is_injection
    _log_suite_event(
        "defense_indirect_injection",
        outcome="intercepted",
        surface="external_content",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_defense_social_engineering(integration_env) -> None:
    r = screen_user_input(
        tp.DEFENSE_SOCIAL_ENGINEERING,
        source="integration.defense_social_engineering",
    )
    assert r.is_injection and r.injection_type == InjectionType.DIRECT_OVERRIDE
    _log_suite_event(
        "defense_social_engineering",
        outcome="intercepted",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_defense_output_weaponization(integration_env) -> None:
    r = screen_user_input(
        tp.DEFENSE_OUTPUT_WEAPONIZATION,
        source="integration.defense_output_weaponization",
    )
    assert r.is_injection
    _log_suite_event(
        "defense_output_weaponization",
        outcome="intercepted",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_defense_abuse_prevention(integration_env) -> None:
    r = screen_user_input(
        tp.DEFENSE_ABUSE_PREVENTION,
        source="integration.defense_abuse_prevention",
    )
    assert r.is_injection and r.injection_type == InjectionType.CREDENTIAL_EXFIL
    _log_suite_event(
        "defense_abuse_prevention",
        outcome="intercepted",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_defense_input_validation(integration_env) -> None:
    r = screen_user_input(
        tp.DEFENSE_INPUT_VALIDATION,
        source="integration.defense_input_validation",
    )
    assert r.is_injection and r.injection_type == InjectionType.MARKUP_INJECTION
    _log_suite_event(
        "defense_input_validation",
        outcome="intercepted",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_defense_database_destruction(integration_env) -> None:
    run_id = uuid.uuid4().int % 1_000_000_000
    with pytest.raises(AgentKilledError):
        screen_agent_action(
            tp.DEFENSE_DATABASE_DESTRUCTION,
            run_id=run_id,
            source="integration.defense_database_destruction",
        )
    _log_suite_event(
        "defense_database_destruction",
        outcome="critical_halting",
        surface="destructive_action_guard",
    )
    _assert_cloud_posts(integration_env)
    _reset_for_tests()


def test_defense_never_guess_destructive(integration_env) -> None:
    result = screen_action(tp.DEFENSE_NEVER_GUESS_DESTRUCTIVE, surface="integration.never_guess")
    assert result.is_destructive
    assert result.severity == ActionSeverity.CRITICAL
    _log_suite_event(
        "defense_never_guess_destructive",
        outcome="destructive_sql_flagged",
        severity=result.severity.value,
    )
    _assert_cloud_posts(integration_env)


def test_defense_kill_switch_awareness(integration_env) -> None:
    r = screen_user_input(
        tp.DEFENSE_KILL_SWITCH_AWARENESS,
        source="integration.defense_kill_switch_awareness",
    )
    assert r.is_injection and r.injection_type == InjectionType.CONTEXT_MANIPULATION
    _log_suite_event(
        "defense_kill_switch_awareness",
        outcome="intercepted",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


# --- OWASP LLM Top 10 (2025) ---------------------------------------------------


def test_owasp_llm01_prompt_injection(integration_env) -> None:
    r = screen_user_input(tp.OWASP_LLM01_PROMPT_INJECTION, source="integration.owasp.llm01")
    assert r.is_injection
    _log_suite_event("owasp_llm01_prompt_injection", guideline="LLM01:2025", threat=r.threat_level.value)
    _assert_cloud_posts(integration_env)


def test_owasp_llm02_sensitive_information_disclosure(integration_env) -> None:
    r = screen_user_input(tp.OWASP_LLM02_SENSITIVE_INFO_DISCLOSURE, source="integration.owasp.llm02")
    assert r.is_injection
    _log_suite_event(
        "owasp_llm02_sensitive_information_disclosure",
        guideline="LLM02:2025",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_llm03_supply_chain(integration_env) -> None:
    r = screen_user_input(tp.OWASP_LLM03_SUPPLY_CHAIN, source="integration.owasp.llm03")
    assert r.is_injection
    _log_suite_event("owasp_llm03_supply_chain", guideline="LLM03:2025", threat=r.threat_level.value)
    _assert_cloud_posts(integration_env)


def test_owasp_llm04_data_and_model_poisoning(integration_env) -> None:
    r = screen_user_input(tp.OWASP_LLM04_DATA_MODEL_POISONING, source="integration.owasp.llm04")
    assert r.is_injection
    _log_suite_event(
        "owasp_llm04_data_and_model_poisoning",
        guideline="LLM04:2025",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_llm05_improper_output_handling(integration_env) -> None:
    r = screen_user_input(tp.OWASP_LLM05_IMPROPER_OUTPUT_HANDLING, source="integration.owasp.llm05")
    assert r.is_injection
    _log_suite_event(
        "owasp_llm05_improper_output_handling",
        guideline="LLM05:2025",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_llm06_excessive_agency(integration_env) -> None:
    run_id = uuid.uuid4().int % 1_000_000_000
    with pytest.raises(AgentKilledError):
        screen_agent_action(
            tp.OWASP_LLM06_EXCESSIVE_AGENCY,
            run_id=run_id,
            source="integration.owasp.llm06",
        )
    _log_suite_event("owasp_llm06_excessive_agency", guideline="LLM06:2025", outcome="critical_halting")
    _assert_cloud_posts(integration_env)
    _reset_for_tests()


def test_owasp_llm07_system_prompt_leakage(integration_env) -> None:
    r = screen_user_input(tp.OWASP_LLM07_SYSTEM_PROMPT_LEAKAGE, source="integration.owasp.llm07")
    assert r.is_injection
    _log_suite_event(
        "owasp_llm07_system_prompt_leakage",
        guideline="LLM07:2025",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_llm08_vector_embedding_weaknesses(integration_env) -> None:
    r = screen_user_input(tp.OWASP_LLM08_VECTOR_EMBEDDING, source="integration.owasp.llm08")
    assert r.is_injection
    _log_suite_event(
        "owasp_llm08_vector_embedding_weaknesses",
        guideline="LLM08:2025",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_llm09_misinformation(integration_env) -> None:
    r = screen_user_input(tp.OWASP_LLM09_MISINFORMATION, source="integration.owasp.llm09")
    assert r.is_injection
    _log_suite_event("owasp_llm09_misinformation", guideline="LLM09:2025", threat=r.threat_level.value)
    _assert_cloud_posts(integration_env)


def test_owasp_llm10_unbounded_consumption(integration_env) -> None:
    r = screen_user_input(tp.OWASP_LLM10_UNBOUNDED_CONSUMPTION, source="integration.owasp.llm10")
    assert r.is_injection
    _log_suite_event(
        "owasp_llm10_unbounded_consumption",
        guideline="LLM10:2025",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


# --- OWASP Agentic (ASI01–ASI10) -----------------------------------------------


def test_owasp_asi01_agent_goal_hijack(integration_env) -> None:
    r = screen_user_input(tp.OWASP_ASI01_AGENT_GOAL_HIJACK, source="integration.owasp.asi01")
    assert r.is_injection
    _log_suite_event("owasp_asi01_agent_goal_hijack", guideline="ASI01", threat=r.threat_level.value)
    _assert_cloud_posts(integration_env)


def test_owasp_asi02_tool_misuse_exploitation(integration_env) -> None:
    r = screen_user_input(tp.OWASP_ASI02_TOOL_MISUSE, source="integration.owasp.asi02")
    assert r.is_injection
    _log_suite_event(
        "owasp_asi02_tool_misuse_exploitation",
        guideline="ASI02",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_asi03_identity_privilege_abuse(integration_env) -> None:
    r = screen_user_input(tp.OWASP_ASI03_IDENTITY_PRIVILEGE, source="integration.owasp.asi03")
    assert r.is_injection
    _log_suite_event(
        "owasp_asi03_identity_privilege_abuse",
        guideline="ASI03",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_asi04_agentic_supply_chain(integration_env) -> None:
    r = screen_user_input(tp.OWASP_ASI04_AGENTIC_SUPPLY_CHAIN, source="integration.owasp.asi04")
    assert r.is_injection
    _log_suite_event(
        "owasp_asi04_agentic_supply_chain",
        guideline="ASI04",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_asi05_unexpected_code_execution(integration_env) -> None:
    r = screen_user_input(tp.OWASP_ASI05_UNEXPECTED_CODE_EXECUTION, source="integration.owasp.asi05")
    assert r.is_injection
    _log_suite_event(
        "owasp_asi05_unexpected_code_execution",
        guideline="ASI05",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_asi06_memory_context_poisoning(integration_env) -> None:
    r = screen_user_input(tp.OWASP_ASI06_MEMORY_CONTEXT_POISONING, source="integration.owasp.asi06")
    assert r.is_injection
    _log_suite_event(
        "owasp_asi06_memory_context_poisoning",
        guideline="ASI06",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_asi07_insecure_inter_agent_communication(integration_env) -> None:
    r = screen_user_input(tp.OWASP_ASI07_INSECURE_INTER_AGENT, source="integration.owasp.asi07")
    assert r.is_injection
    _log_suite_event(
        "owasp_asi07_insecure_inter_agent_communication",
        guideline="ASI07",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_asi08_cascading_failures(integration_env) -> None:
    r = screen_user_input(tp.OWASP_ASI08_CASCADING_FAILURES, source="integration.owasp.asi08")
    assert r.is_injection
    _log_suite_event(
        "owasp_asi08_cascading_failures",
        guideline="ASI08",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_asi09_human_agent_trust_exploitation(integration_env) -> None:
    r = screen_user_input(tp.OWASP_ASI09_HUMAN_AGENT_TRUST, source="integration.owasp.asi09")
    assert r.is_injection
    _log_suite_event(
        "owasp_asi09_human_agent_trust_exploitation",
        guideline="ASI09",
        threat=r.threat_level.value,
    )
    _assert_cloud_posts(integration_env)


def test_owasp_asi10_rogue_agents(integration_env) -> None:
    r = screen_user_input(tp.OWASP_ASI10_ROGUE_AGENTS, source="integration.owasp.asi10")
    assert r.is_injection
    _log_suite_event("owasp_asi10_rogue_agents", guideline="ASI10", threat=r.threat_level.value)
    _assert_cloud_posts(integration_env)


# --- Optional heavy inference --------------------------------------------------


@pytest.mark.skipif(
    os.environ.get("COGNEXUS_RUN_MODEL_SMOKE") != "1",
    reason="Set COGNEXUS_RUN_MODEL_SMOKE=1 to download/run the Qwen smoke test.",
)
def test_optional_qwen_smoke_inference(integration_env) -> None:
    pytest.importorskip("torch")
    pytest.importorskip("transformers")

    from transformers import AutoModelForCausalLM, AutoTokenizer
    import torch

    model_id = "Qwen/Qwen3-4B-Instruct-2507"
    dtype = torch.float16 if torch.cuda.is_available() else torch.float32
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    kwargs: dict = {"dtype": dtype, "trust_remote_code": True}
    try:
        import accelerate  # noqa: F401

        if torch.cuda.is_available():
            kwargs["device_map"] = "auto"
    except ImportError:
        pass
    model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs)
    if "device_map" not in kwargs:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)

    system = augment_system_prompt("You are a concise assistant.")
    report = evaluate_system_prompt(system)
    assert report.grade in {"A", "B"}

    safe_user = "Summarise two benefits of unit testing in one sentence."
    safe_result = screen_user_input(safe_user, source="integration.qwen_smoke.safe")
    assert not safe_result.is_injection
    maybe_log_prompt_defense(__import__("logging").getLogger("integration"), system, context="qwen_smoke")

    malicious_user = tp.DEFENSE_INSTRUCTION_OVERRIDE
    bad_result = screen_user_input(malicious_user, source="integration.qwen_smoke.blocked")
    assert bad_result.is_injection

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": safe_user},
    ]
    input_ids = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
        return_tensors="pt",
    )
    if not torch.cuda.is_available():
        input_ids = input_ids.to(model.device if hasattr(model, "device") else next(model.parameters()).device)
    with torch.no_grad():
        out = model.generate(input_ids, max_new_tokens=32, do_sample=False)

    text = tokenizer.decode(out[0], skip_special_tokens=True)
    assert len(text) > 0

    post_sdk_event(
        "integration_qwen_smoke",
        title="artzain.integration.qwen_smoke",
        payload={
            "model": model_id,
            "safe_screen_clean": not safe_result.is_injection,
            "malicious_screen_hit": bad_result.is_injection,
            "system_grade": report.grade,
        },
    )
    _assert_cloud_posts(integration_env)


def test_static_prompt_audit_flags_weak_prompt(integration_env) -> None:
    """Augmented prompts grade well; bare prompts score poorly — static defence audit."""

    bare = evaluate_system_prompt("You are a helpful assistant.")
    hardened = evaluate_system_prompt(augment_system_prompt("You are a helpful assistant."))
    assert bare.score < hardened.score
    _log_suite_event(
        "static_prompt_audit_delta",
        bare_grade=bare.grade,
        hardened_grade=hardened.grade,
    )
    _assert_cloud_posts(integration_env)
